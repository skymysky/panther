// flushdeletedresources opstool removes all entries from the panther-resources table where deleted=true
package main

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	// Go Packages
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Internal / panther packages
	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"

	// AWS packages
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	// Logging and errors
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const tableName = "panther-resources"
const maxBackoff = 60 * time.Second

// version set by mage build:tools
var version string

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	startTime := time.Now()

	debug, flush, inspect, save, versionOpt := getOpts()

	if versionOpt {
		_, BIN, ARCH, OS := binMeta()
		printfln("ARCH=%v", ARCH)
		printfln("BIN=%v", BIN)
		printfln("OS=%v", OS)
		printfln("VERSION=%v", version)
		return
	}

	log := opstools.MustBuildLogger(debug)
	log.Debug("STARTEPOCH=", startTime.Unix())

	// Debug log the CLI options values
	if !flush && !save && !inspect {
		flag.Usage()
	}

	// Save, Flush and Inspect require an aws session which can take a few seconds to fail so
	// we print the command before proceeding for user experience
	if save {
		printfln("SAVE")
	}
	if flush {
		printfln("FLUSH")
	}
	if inspect {
		printfln("INSPECT")
	}

	var auditFile *os.File

	// This will catch any calls to panic and close/remove the audit file if necessary
	defer func() {
		var recoveryErr error = nil
		exitCode := 0

		// Catches calls to panic
		if r := recover(); r != nil {
			log.Debug("PANIC ERROR RECOVERY")
			if err, ok := r.(error); ok {
				recoveryErr = err
			}
		}

		// Close the file and remove file depending on boolean of 3rd parameter and file is empty
		if err := cleanup(log, auditFile, true); err != nil {
			log.Error(err)
			exitCode = 1
		}

		if recoveryErr != nil {
			exitCode = 1
			if awsErr, ok := recoveryErr.(awserr.Error); ok {
				switch awsErr {
				case credentials.ErrNoValidProvidersFoundInChain:
					log.Debug("credentials.ErrNoValidProvidersFoundInChain")
					log.Error("AWS NoCredentialProviders Error: No valid providers in chain")
				default:
					log.Debug("Unhandled aws error")
					log.Error("aws error: %v", awsErr)
				}
			} else {
				log.Error("\n%v\n", recoveryErr)
			}
		}

		printfln("Completed in %.2f seconds", time.Since(startTime).Seconds())
		os.Exit(exitCode)
	}()

	if save {
		// basename
		writeFName := fmt.Sprintf("flush_resource_ids_%v", startTime.Unix())
		log.Debug("WRITEFNAME=", writeFName)

		// destination directory path
		writeDir, err := os.Getwd()
		check(err)
		log.Debug("WRITEDIR=", writeDir)

		// Audit file full path
		auditFilePath := filepath.Join(writeDir, writeFName)
		log.Debug("AUDITFILEPATH=", auditFilePath)

		// Create the file
		auditFile, err = os.Create(auditFilePath)
		check(err)
	}

	// init dynamodb svc client
	awsSession, err := session.NewSession()
	check(err)

	// Execute the scan, save, and flush (depending on params)
	FlushSaveInspectResources(dynamodb.New(awsSession), auditFile, flush, save, inspect)
}

// Closes auditFile and removes when auditfile sz is 0 and rmEmptyFile is true
func cleanup(log *zap.SugaredLogger, auditFile *os.File, rmEmptyFile bool) error {
	log.Debug("RMEMPTYFILE=", rmEmptyFile)
	// Check / close the audit file
	if auditFile == nil {
		return nil
	}

	auditFPath := auditFile.Name()
	log.Debug("AUDITFILEPATH=", auditFPath)

	// Close the file after getting the file stats, check for stat errors after closing the file
	auditFStat, err := auditFile.Stat()
	log.Debug("Close auditFile")
	auditFile.Close()
	if err != nil {
		return err
	}
	auditFSize := auditFStat.Size()
	if !rmEmptyFile || auditFSize > 0 {
		return nil
	}
	log.Debug("AUDITFILESIZE=", auditFSize)
	if err = os.Remove(auditFPath); err != nil {
		return err
	}
	log.Debug("Removed ", auditFPath)
	return nil
}

// Flush runs all the inspect, flush, and save commands. This method can be called on its own
// assuming the inputs are valid.
func FlushSaveInspectResources(svc *dynamodb.DynamoDB, saveWriter io.Writer, flush, save, inspect bool) {
	// Check if the scanAuditFlushResources method has nothing to do
	if !flush && !save && !inspect {
		check(errors.New("FlushSaveInspectResources requires flush, inspect, or a valid writer and save"))
	}

	// Store write requests for items scanned in svc.ScanPages using the scanInput expression
	deleteRequests := []*dynamodb.WriteRequest{}

	// Build the scan expression
	proj := expression.NamesList(expression.Name("id"))
	filt := expression.Name("deleted").Equal(expression.Value(true))
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	check(err)

	// define params used in call to ScanPages
	scanInput := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}
	resultScanner := func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			deleteEntry := &dynamodb.WriteRequest{DeleteRequest: &dynamodb.DeleteRequest{Key: item}}
			if save {
				_, err := saveWriter.Write([]byte(*item["id"].S + "\n"))
				check(err)
			}
			// Add the delete request to the set
			deleteRequests = append(deleteRequests, deleteEntry)
		}
		return !lastPage
	}

	// SCAN THE DYNAMODB
	check(svc.ScanPages(scanInput, resultScanner))
	flush = flush && len(deleteRequests) > 0

	printfln("Items pending deletion: %v", len(deleteRequests))

	if inspect && len(deleteRequests) > 0 {
		// Set initial size to length of items to add size of required newline characters
		var sumSz int64 = int64(len(deleteRequests))
		for _, item := range deleteRequests {
			sumSz += int64(len(*item.DeleteRequest.Key["id"].S))
		}
		printfln("Save file estimated size: %v", humanByteSize(sumSz))
	}
	if flush {
		// Batch write request parameter containing set of delete item requests
		batchWriteInput := &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]*dynamodb.WriteRequest{tableName: deleteRequests},
		}
		printfln("Beginning Batch Delete")
		check(dynamodbbatch.BatchWriteItem(svc, maxBackoff, batchWriteInput))
		printfln("Completed Batch Delete")
	}
}

// Parses the name of the binary to retrieve the GOOS, GOARCH, Binary Name and the tool Name.
func binMeta() (NAME, BIN, ARCH, OS string) {
	BIN = filepath.Base(os.Args[0])
	versionMeta := strings.Split(BIN, "-")
	ARCH = versionMeta[2]
	NAME = versionMeta[0]
	OS = versionMeta[1]
	return
}

// returns values of the required cli options where true means the option was specified in the cli args.
func getOpts() (debug, flush, inspect, save, versionOpt bool) {
	flag.Usage = usage
	cliDebug := flag.Bool("debug", false, "Enable debug logging")
	cliFlush := flag.Bool("flush", false, "Remove entries from the panther-resources table where deleted=true")
	cliInspect := flag.Bool("inspect", false, "Print number of panther-resources entries where delete=true and the estimated save file size")
	cliSave := flag.Bool("save", false, "Save Id's of panther-resources entries where delete=true to ./flush_resource_ids_<start_epoch>")
	cliVersion := flag.Bool("version", false, "Print ARCH, BIN, OS, and VERSION")
	flag.Parse()
	debug = *cliDebug
	flush = *cliFlush
	inspect = *cliInspect
	save = *cliSave
	versionOpt = *cliVersion
	// If Inspect is specified we disable save and flush
	flush = flush && !inspect
	save = save && !inspect
	return
}

// COSMETIC Helpers:
func usage() {
	NAME, BIN, _, _ := binMeta()
	printfln("\n%v\n", NAME)
	printfln("  Remove entries from the resources table where entry deleted=true\n")
	printfln("  Entries in the resources table are set as deleted and scheduled for deletion.")
	printfln("  This can lead to a large number of entries that have been deleted from Panther")
	printfln("  but are pending deletion from the resources table.\n")
	printfln("  This tool removes all entries from the resources table which have been deleted")
	printfln("  from Panther but are pending deletion from the table.\n")
	printfln("  Save is not necessary for most users. Use inspect before save to view the number")
	printfln("  of items with delete=true, and to see the estimated file size of the save file.\n")
	printfln("  Inspect and version will return without running save or flush.\n")
	printfln("  Save will not create a file when the resources table has no entries pending")
	printfln("  deletion\n")
	printfln("  Flush is the only option that will remove entries from the resources table\n")
	printfln("REQUIREMENTS:\n")
	printfln("  This tool requires aws credentials with dynamodb panther-resources table permissions:\n")
	printfln("  BatchWriteItem")
	printfln("  Scan\n")
	printfln("USAGE:\n\n  %v <options>\n", BIN)
	printfln("Where options are:\n")
	flag.PrintDefaults()
	printfln()
	os.Exit(0)
}
func printfln(args ...interface{}) {
	if len(args) == 1 {
		fmt.Fprintf(flag.CommandLine.Output(), args[0].(string))
	} else if len(args) > 1 {
		fmt.Fprintf(flag.CommandLine.Output(), args[0].(string), args[1:]...)
	}
	fmt.Fprintf(flag.CommandLine.Output(), "\n")
}
func humanByteSize(b int64) string {
	if b < 1000 {
		return fmt.Sprintf("%d Bytes", b)
	}
	divider := int64(1000)
	exponent := 0
	for n := b / 1000; n >= 1000; n /= 1000 {
		divider *= 1000
		exponent++
	}
	szUnits := [5]string{"kB", "MB", "GB", "TB"}
	unitSz := float64(b) / float64(divider)
	return fmt.Sprintf("%.2f %s", unitSz, szUnits[exponent])
}
