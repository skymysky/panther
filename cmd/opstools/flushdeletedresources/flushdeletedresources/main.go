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

	// AWS packages
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	// Logging and errors
	"go.uber.org/zap"
	"github.com/pkg/errors"
)

const tableName = "panther-resources"

// Set by mage build:tools
var version string

// Output when user enables debugging with the -d flag
// var log *zap.SugaredLogger

// Struct used to capture user iput
type CLIOpts struct {
	Audit, 									// Write panther-resources item IDs to a file where item deleted=true
	Debug, 			   					// Enable debug logging
	Flush, 									// Remove panther-resources items where deleted=true
	RmEmptyAuditFile *bool // Delete Audit file when file is empty at tool completion
}

var opts CLIOpts
var startTime time.Time
var logger *zap.SugaredLogger

func init() {
	startTime = time.Now()
	opts = getOpts()
	logger = opstools.MustBuildLogger(*opts.Debug)
	flag.Usage = usage
}

func main() {
	var auditFile *os.File
	defer cleanup(auditFile)

	if !*opts.Flush && !*opts.Audit {
		flag.Usage()
		return
	}

	// If user specified Audit, Generate the audit file destination basename and full directory
	// and create the file ./flush_resources_audit_<start_unix_epoch_time>
	if *opts.Audit {
		writeFName := fmt.Sprintf("flush_resources_audit_%v", startTime.Unix())
		writeDir, err := os.Getwd()
		check(err)
		auditFilePath := filepath.Join(writeDir, writeFName)
		auditFile, err = os.Create(auditFilePath)
		check(err)
	}

	///ScanAuditFlushResources(*opts.Flush, auditFile)
}

func getOpts() CLIOpts {
	opts := CLIOpts{
		// Write the id of each table entry where deleted=true to an audit file
		Audit: flag.Bool("a", false, "Audit - Writes the ID of every delete=true item on a separate line to ./flush_resources_audit_<start_epoch_time>"),
		// Debug is used for debug logging only. This does not affect the functionality of the flush script
		Debug: flag.Bool("d", false, "Debug - Set debug to true, enables debug logging"),
		// Remove deleted=true entries from the panther-resources table
		Flush: flag.Bool("f", false, "FLUSH - Delete panther-resources entries from panther-resources table where deleted=true"),
		// Removes the audit file if nothing was written to the audit file when the flush tool completes
		RmEmptyAuditFile: flag.Bool("c", false, "Clean - Removes the audit file if the file is empty when the tool completes"),
	}
	flag.Parse()
	return opts
}

func cleanup(auditFile *os.File) {

	fmt.Printf("\n CLEANUP\n")

	// Catch any panic errors
	if r := recover(); r != nil {
		// onErr(err)
		fmt.Printf("Recovered in f", r)
	} else {
		fmt.Printf("\n Did Not Recover!")
	}

	// Check / close the audit file
	if auditFile != nil {
		var auditFSize int64 = -1
		auditFPath := ""
		auditFStat, err := auditFile.Stat()
		auditFPath = auditFile.Name()
		if err != nil {
			fmt.Printf("\n Audit File Error! %v\n", err)
		} else {
			auditFSize = auditFStat.Size()
		}
		auditFile.Close()

		fmt.Printf(" audit file: %v\n", auditFile)

		if *opts.RmEmptyAuditFile && auditFSize == 0 {
			fmt.Printf("\n REMOVE FILE AT %v\n", auditFPath)
		}
	}


	/*
		fmt.Printf("\n auditFile Not NIL!\n")
	} else {
		fmt.Printf("\n auditFile is NIL!\n")
	}
	fmt.Printf("\n\n Deferred Method!!!\n\n")
	if auditFile != nil {
		afstat, err := auditFile.Stat();
		fmt.Printf("\n\n Closing Audit File\n\n")
		auditFile.Close()
		fmt.Printf("\n fstat size: %v\n", afstat.Size())
		fmt.Printf("f.stat err %v\n", err)
	} else {
		fmt.Printf("No Audit File!!!\n")
	}
	*/
}

// ScanAuditFlushResources
func ScanAuditFlushResources(flush bool, writeOut io.Writer) {
	// Check if the scanAuditFlushResources method has nothing to do
	if !flush && writeOut == nil {
		check(errors.New("you must specify atleast 1 option (besides debug). Either -f or -a"))
	}

	// init dynamodb svc client
	awsSession := session.Must(session.NewSession())
	dynamosvc := dynamodb.New(awsSession)

	// Slice passed to the batchWriteItem representing the set of all items to remove from the table
	var deleteRequests []*dynamodb.WriteRequest

	// Scan for deleted entries and populate the deleteRequests with the id from any scanned item
	// returned by scanning with the input from the getScanDeleteExpr
	check(dynamosvc.ScanPages(getScanDeletedExpr(), getResultScanner(deleteRequests, writeOut)))

	// Skip flush if user never specified the flush option
	if flush {
		/*
		// Exit before calling batch write if no items are found
		if len(deleteRequests) == 0 {
			sugar.Info("Resources table scan found no entries where deleted=true\n")
			os.Exit(0)
		}

		// Batch write request parameter containing set of delete item requests
		batchWriteInput := &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]*dynamodb.WriteRequest{tableName: deleteRequests},
		}

		// Execute the batch deletions
		maxBackoff := 10 * time.Second
		if err = dynamodbbatch.BatchWriteItem(client, maxBackoff, batchWriteInput); err != nil {
			sugar.Errorf("BatchWriteItem error: %s\n", err)
			os.Exit(1)
		}

		sugar.Infof("Flushed %v deleted entries\n", len(deleteRequests))
		os.Exit(0)
		*/
	}
}




// Catches all errors in the flushdeletedresources tool
// all errors are the parameter in panic called in the check method
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// Returns the function called for each result from a ScanPages call.
//
// Each scan item returned is assed to the toDelete WriteRequest slice.
// When the user specifies the audit option, results are written to the passed writer
func getResultScanner(toDelete []*dynamodb.WriteRequest, writeOut io.Writer) (func(*dynamodb.ScanOutput, bool) bool) {
	return func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			// Delete request for the scan result item
			deleteEntry := &dynamodb.WriteRequest{DeleteRequest: &dynamodb.DeleteRequest{Key: item}}
			// check if we need to record the id (determined by user specifying the audit flag)
			if writeOut != nil {
				if id, ok := item["id"]; ok {
					fmt.Printf("ID: %v\n", *id.S)
					_, err := writeOut.Write([]byte(*id.S))
					check(err)
				}
			}
			// Add the delete request to the set
			toDelete = append(toDelete, deleteEntry)
		}
		return !lastPage
	}
}

// Returns dynmodb.ScanInput used in ScanPages to get only the resources where delete=true
func getScanDeletedExpr() *dynamodb.ScanInput {
	proj := expression.NamesList(expression.Name("id"))
	// proj := expression.NamesList(expression.Name("id"), expression.Name("deleted"))
	filt := expression.Name("deleted").Equal(expression.Value(true))
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	check(err)

	// Scan entries with the specified expression above
	// https://docs.aws.amazon.com/sdk-for-go/api/service/dynamodb/#ScanInput
	scanInput := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}

	return scanInput
}

// COSMETIC Helpers:
// Helpers for beautifying io
func usage() {
	binMeta := strings.Split(filepath.Base(os.Args[0]), "-")
	printfln()
	printfln("%s", binMeta[0])
	printfln()
	printfln("Removes table entries from panther-resource table where item deleted=true")
	printfln()
	printfln("OS=%s", binMeta[1])
	printfln("ARCH=%s", binMeta[2])
	printfln("VERSION=%s", version)
	printfln()
	printfln("USAGE:")
	flag.PrintDefaults()
	printfln()
}
func printfln(args ...interface{}) {
	if len(args) == 1 {
		fmt.Fprintf(flag.CommandLine.Output(), args[0].(string))
	} else if len(args) > 1 {
		fmt.Fprintf(flag.CommandLine.Output(), args[0].(string), args[1:]...)
	}
	fmt.Fprintf(flag.CommandLine.Output(), "\n")
}

/*

if writeFile != nil {
	writeFile.Close()
}
// Audit file was created, Flush count was zero (no items written to audit file) and
// the user never specified
if flushCount == 0 && writeFile != nil && *removeEmptyAuditFile {
	fmt.Printf("\n\n No items flushed... must remove the audit file")
}
*/

/*
// Never remove the audit file regardless of the flush count
if !*removeEmptyAuditFile || writeFile == nil {
	return
}
*/


/*
if err == nil && *opts.RmEmptyAuditFile {

}
// Check if file length is zero
*/

		/*
		func() {
			if r := recover(); r != nil {
				// onErr(err)
				fmt.Println("Recovered in f", r)
			}
		}()
		flag.Usage()
		printfln(err.Error())
		*/


	/*
	if writeFile != nil {
		fmt.Printf(" \n\n DONT FORGET TO CLOSE THE FILE!\n")
		defer writeFile.Close()
	} else {
		fmt.Printf(" \n\n NO FILE CREATED\n")
	}
	*/

/*
"time"
"log"
"go.uber.org/zap"
"go.uber.org/zap/zapcore"
"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"

// Dynamdb scan expression If you would like to see the value of deleted (or any other field) add
// it to the projection names set.
if err != nil {
	sugar.Error(err)
	os.Exit(1)
}

// Scan for deleted entries
if err = client.ScanPages(input, scanResult); err != nil {
	sugar.Error(err)
	os.Exit(1)
}

// Flush table
// Explicitly delete columns in the panther-resources table where the table entry deleted is equal
// to the entrydeleted contant
// const entrydeleted = true
// var awsSession *session.Session
// var sugar *zap.SugaredLogger
*/
