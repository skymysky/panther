package cost

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
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/costexplorer"
	"github.com/aws/aws-sdk-go/service/costexplorer/costexploreriface"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
)

// Specifically tailored reports for Panther

const (
	DateFormat = "2006-01-02"
	// The minimum amount of cost to be considered in the cost reports. Reduces noise by eliminating
	// any costs that accumulated less than one cent in a month
	secondsPerDay = 86400
	noAlias       = "NO-ALIAS-SET"
)

var (
	services = []string{
		"AWS AppSync",
		"Amazon Athena",
		"Amazon Cognito",
		"AmazonCloudWatch",
		"Amazon EC2 Container Registry (ECR)",
		"Amazon Elastic File System",
		"Amazon Elastic Load Balancing",
		"Amazon DynamoDB",
		"Amazon Kinesis Firehose",
		"AWS Glue",
		"AWS Key Management Service",
		"AWS Lambda",
		"Amazon Simple Storage Service",
		"AWS Secrets Manager", // nolint:gosec
		"Amazon Simple Queue Service",
		"Amazon Simple Notification Service",
		"AWS Step Functions",
	}
)

type PantherOpsReports struct {
	// Input fields
	Start, End       time.Time
	Granularity      string
	DetailedServices []string // services to expand
	AccountId        string

	// Clients
	cwClient     cloudwatchiface.CloudWatchAPI
	lambdaClient lambdaiface.LambdaAPI
	ceClient     costexploreriface.CostExplorerAPI

	// Queried fields
	AccountName      string
	Region           string
	LambdaComponents map[string]string
	LambdaMemories   map[string]int64

	// Specific reports used for our standardized billing & usage tracking
	BytesProcessedQuery *cloudwatch.GetMetricDataInput
	BytesProcessed      []PantherBytesProcessedRow

	LambdaUsageQuery *cloudwatch.GetMetricDataInput
	LambdaUsage      []PantherLambdaUsageRow

	S3UsageQuery *cloudwatch.GetMetricDataInput
	S3Usage      []PantherS3StorageRow

	ServiceCostQueries []*costexplorer.GetCostAndUsageInput
	ServiceCost        []PantherServiceCostRow

	ResourceCostQuery *costexplorer.GetCostAndUsageInput
	ResourceCost      []PantherResourceCostRow
}

func (r *Reporter) NewPantherOpsReports(startTime, endTime time.Time, granularity, accountId string,
	detailedServices []string) (*PantherOpsReports, error) {

	startTime = startTime.UTC()
	endTime = endTime.UTC()
	awsSession := session.Must(session.NewSession())

	iamClient := iam.New(awsSession)
	aliases, err := iamClient.ListAccountAliases(&iam.ListAccountAliasesInput{})
	if err != nil {
		return nil, err
	}
	accountName := noAlias
	if len(aliases.AccountAliases) > 0 {
		accountName = *aliases.AccountAliases[0]
	}

	report := &PantherOpsReports{
		AccountId:        accountId,
		AccountName:      accountName,
		Start:            startTime,
		End:              endTime,
		Granularity:      granularity,
		DetailedServices: detailedServices,
		cwClient:         cloudwatch.New(awsSession),
		lambdaClient:     lambda.New(awsSession),
		ceClient:         costexplorer.New(awsSession),
		Region:           *awsSession.Config.Region,
		LambdaComponents: make(map[string]string, 0),
		LambdaMemories:   make(map[string]int64, 0),
	}

	report.BytesProcessedQuery = &cloudwatch.GetMetricDataInput{
		EndTime: &endTime,
		MetricDataQueries: []*cloudwatch.MetricDataQuery{
			{
				Expression: aws.String(`SEARCH('{Panther,LogType} MetricName=\"BytesProcessed\" ', 'Sum', 86400)`),
				Id:         aws.String("bytes1"),
				Period:     aws.Int64(secondsPerDay),
				ReturnData: aws.Bool(true),
			},
		},
		StartTime: &startTime,
	}

	report.LambdaUsageQuery = &cloudwatch.GetMetricDataInput{
		EndTime: &endTime,
		MetricDataQueries: []*cloudwatch.MetricDataQuery{
			{
				Expression: aws.String(`SEARCH('{AWS/Lambda,FunctionName} FunctionName=\"panther-*\" MetricName=\"Duration\"', 'Sum', 86400)`),
				Id:         aws.String("duration"),
				Period:     aws.Int64(secondsPerDay),
				ReturnData: aws.Bool(true),
			},
			{
				Expression: aws.String(`SEARCH('{AWS/Lambda,FunctionName} FunctionName=\"panther-*\" MetricName=\"Invocations\"', 'Sum', 86400)`),
				Id:         aws.String("invocations"),
				Period:     aws.Int64(secondsPerDay),
				ReturnData: aws.Bool(true),
			},
		},
		StartTime: &startTime,
	}

	report.S3UsageQuery = &cloudwatch.GetMetricDataInput{
		EndTime: &endTime,
		MetricDataQueries: []*cloudwatch.MetricDataQuery{
			{
				Expression: aws.String(`SEARCH('{AWS/S3,BucketName,StorageType} MetricName=\"BucketSizeBytes\" processeddata', 'Average', 86400)`),
				Id:         aws.String("processed_data"),
				Period:     aws.Int64(secondsPerDay),
				ReturnData: aws.Bool(true),
			},
			{
				Expression: aws.String(`SEARCH('{AWS/S3,BucketName,StorageType} MetricName=\"BucketSizeBytes\" historicaldata', 'Average', 86400)`),
				Id:         aws.String("historical_data"),
				Period:     aws.Int64(secondsPerDay),
				ReturnData: aws.Bool(true),
			},
		},
		StartTime: &startTime,
	}

	// We need one query per service because AWS only allows two group by definitions per query
	for _, service := range services {
		report.ServiceCostQueries = append(report.ServiceCostQueries, &costexplorer.GetCostAndUsageInput{
			Filter: &costexplorer.Expression{
				And: []*costexplorer.Expression{
					{
						Dimensions: &costexplorer.DimensionValues{
							Key:    aws.String(costexplorer.DimensionService),
							Values: []*string{aws.String(service)},
						},
					},
					{
						Tags: &costexplorer.TagValues{
							Key: aws.String("Stack"),
							Values: []*string{
								aws.String("panther-bootstrap"),
								aws.String("panther-bootstrap-gateway"),
								aws.String("panther-cloud-security"),
								aws.String("panther-core"),
								aws.String("panther-log-analysis"),
								aws.String("panther-onboard"),
							},
						},
					},
				},
			},
			Granularity: aws.String(costexplorer.GranularityDaily),
			//Granularity: aws.String(costexplorer.GranularityMonthly), // also an option
			GroupBy: []*costexplorer.GroupDefinition{
				{
					Key:  aws.String(costexplorer.DimensionUsageType),
					Type: aws.String(costexplorer.GroupDefinitionTypeDimension), // TAG or CostCategory are the alternatives
				},
				{
					Key: aws.String("Stack"),
					// Key:  aws.String("PantherResource"),
					Type: aws.String(costexplorer.GroupDefinitionTypeTag),
				},
			},
			Metrics: []*string{
				aws.String(costexplorer.MetricUsageQuantity),
				aws.String(costexplorer.MetricUnblendedCost),
			},
			TimePeriod: &costexplorer.DateInterval{
				Start: aws.String(startTime.Format(DateFormat)),
				End:   aws.String(endTime.Format(DateFormat)),
			},
		})
	}

	return report, nil
}

func (pr *PantherOpsReports) Run() error {
	bytesProcessed, err := pr.cwClient.GetMetricData(pr.BytesProcessedQuery)
	if err != nil {
		return err
	}
	for _, bytesProcessedMetric := range bytesProcessed.MetricDataResults {
		for i, value := range bytesProcessedMetric.Values {
			metricTime := bytesProcessedMetric.Timestamps[i]
			pr.BytesProcessed = append(pr.BytesProcessed, PantherBytesProcessedRow{
				AccountId:      pr.AccountId,
				AccountName:    pr.AccountName,
				LogType:        *bytesProcessedMetric.Label,
				BytesProcessed: *value,
				Year:           metricTime.Year(),
				Month:          int(metricTime.Month()),
				Day:            metricTime.Day(),
			})
		}
	}

	// This query gets both the invocations and the durations of each lambda function
	lambdaUsage, err := pr.cwClient.GetMetricData(pr.LambdaUsageQuery)
	if err != nil {
		return err
	}

	// Since we want to make a single row containing both duration & invocation info, first we extract
	// out all the invocation data
	lambdaInvocationMappings := make(map[string]map[time.Time]float64)
	for _, lambdaUsage := range lambdaUsage.MetricDataResults {
		// Need to pull out the lambda name
		lambdaName := strings.Split(*lambdaUsage.Label, " ")[0]
		if *lambdaUsage.Id == "invocations" {
			lambdaInvocationMappings[lambdaName] = make(map[time.Time]float64, len(lambdaUsage.Values))
			for i, value := range lambdaUsage.Values {
				metricTime := lambdaUsage.Timestamps[i]
				lambdaInvocationMappings[lambdaName][*metricTime] = *value
			}
		}
	}

	// Now we extract the duration info, combine it with the invocation info, and lookup some auxiliary info
	for _, lambdaUsage := range lambdaUsage.MetricDataResults {
		if *lambdaUsage.Id == "invocations" {
			continue
		}
		// Need to pull out the lambda name
		lambdaName := strings.Split(*lambdaUsage.Label, " ")[0]
		for i, value := range lambdaUsage.Values {
			metricTime := lambdaUsage.Timestamps[i]
			component, err := pr.getLambdaComponent(lambdaName)
			if err != nil {
				return err
			}
			memory, err := pr.getLambdaMemory(lambdaName)
			if err != nil {
				return err
			}
			pr.LambdaUsage = append(pr.LambdaUsage, PantherLambdaUsageRow{
				AccountId:         pr.AccountId,
				AccountName:       pr.AccountName,
				LambdaName:        lambdaName,
				LambdaDuration:    *value,
				LambdaInvocations: lambdaInvocationMappings[lambdaName][*metricTime],
				LambdaMemory:      memory,
				Component:         component,
				Year:              metricTime.Year(),
				Month:             int(metricTime.Month()),
				Day:               metricTime.Day(),
			})
		}
	}

	s3Usage, err := pr.cwClient.GetMetricData(pr.S3UsageQuery)
	if err != nil {
		return err
	}
	for _, s3UsageMetric := range s3Usage.MetricDataResults {
		for i, value := range s3UsageMetric.Values {
			metricTime := s3UsageMetric.Timestamps[i]
			pr.S3Usage = append(pr.S3Usage, PantherS3StorageRow{
				AccountId:   pr.AccountId,
				AccountName: pr.AccountName,
				Bucket:      *s3UsageMetric.Label,
				// Specifically hard coded this in the request to make this work
				StorageType: *s3UsageMetric.Id,
				Bytes:       *value,
				Year:        metricTime.Year(),
				Month:       int(metricTime.Month()),
				Day:         metricTime.Day(),
			})
		}
	}

	for _, query := range pr.ServiceCostQueries {
		for {
			reports, err := pr.ceClient.GetCostAndUsage(query)
			if err != nil {
				return err
			}
			for _, result := range reports.ResultsByTime {
				for _, group := range result.Groups {
					cost, err := strconv.ParseFloat(*group.Metrics["UnblendedCost"].Amount, 64)
					if err != nil {
						return err
					}
					usage, err := strconv.ParseFloat(*group.Metrics["UsageQuantity"].Amount, 64)
					if err != nil {
						return err
					}
					service := *query.Filter.And[0].Dimensions.Values[0]

					timestamp, err := time.Parse(DateFormat, *result.TimePeriod.Start)
					if err != nil {
						return err
					}
					pr.ServiceCost = append(pr.ServiceCost, PantherServiceCostRow{
						AccountId:    pr.AccountId,
						AccountName:  pr.AccountName,
						Service:      service,
						ServiceUsage: usage,
						CostCategory: *group.Metrics["UsageQuantity"].Unit,
						Cost:         cost,
						Year:         timestamp.Year(),
						Month:        int(timestamp.Month()),
						Day:          timestamp.Day(),
					})
				}
			}
			if reports.NextPageToken == nil {
				break
			}
			query.NextPageToken = reports.NextPageToken
		}
	}

	return nil
}

func (pr PantherOpsReports) getLambdaComponent(lambdaName string) (string, error) {
	if component, ok := pr.LambdaComponents[lambdaName]; ok {
		return component, nil
	}

	lambdaArn := arn.ARN{
		Partition: "aws",
		Service:   "lambda",
		Region:    pr.Region,
		AccountID: pr.AccountId,
		Resource:  "function:" + lambdaName,
	}
	tags, err := pr.lambdaClient.ListTags(&lambda.ListTagsInput{Resource: aws.String(lambdaArn.String())})
	if err != nil {
		return "", err
	}
	component := "NOT_TAGGED"
	if componentCheck, ok := tags.Tags["Stack"]; ok {
		component = *componentCheck
	}
	pr.LambdaComponents[lambdaName] = component
	return component, nil
}

func (pr PantherOpsReports) getLambdaMemory(lambdaName string) (int64, error) {
	if memory, ok := pr.LambdaMemories[lambdaName]; ok {
		return memory, nil
	}

	config, err := pr.lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{FunctionName: &lambdaName})
	if err != nil {
		return 0, err
	}
	pr.LambdaMemories[lambdaName] = *config.MemorySize
	return *config.MemorySize, nil
}

func (pr PantherOpsReports) CSV(fileName string) error {
	if fileName == "" {
		fileName = pr.AccountId
		if pr.AccountName != noAlias {
			fileName = pr.AccountName
		}
		fileName += "_" + pr.Start.Format(DateFormat) + "_" + pr.End.Format(DateFormat)
	}
	bytesProcessedFile, err := os.Create(fileName + "_bytes_processed.csv")
	if err != nil {
		return err
	}

	// accountId, accountName, logType, bytesProcessed, year, month, day
	bytesProcessedWriter := csv.NewWriter(bytesProcessedFile)
	defer bytesProcessedWriter.Flush()
	for _, metric := range pr.BytesProcessed {
		err = bytesProcessedWriter.Write([]string{
			metric.AccountId,
			metric.AccountName,
			metric.LogType,
			fmt.Sprintf("%f", metric.BytesProcessed),
			strconv.Itoa(metric.Year),
			strconv.Itoa(metric.Month),
			strconv.Itoa(metric.Day),
		})
		if err != nil {
			return err
		}
	}

	// accountId, accountName, lambdaName, lambdaDuration, invocations, memory, component, year, month, day
	lambdaUsageFile, err := os.Create(fileName + "_lambda_usage.csv")
	if err != nil {
		return err
	}

	lambdaDurationWriter := csv.NewWriter(lambdaUsageFile)
	defer lambdaDurationWriter.Flush()
	for _, metric := range pr.LambdaUsage {
		err = lambdaDurationWriter.Write([]string{
			metric.AccountId,
			metric.AccountName,
			metric.LambdaName,
			fmt.Sprintf("%f", metric.LambdaDuration),
			fmt.Sprintf("%f", metric.LambdaInvocations),
			fmt.Sprintf("%d", metric.LambdaMemory),
			metric.Component,
			strconv.Itoa(metric.Year),
			strconv.Itoa(metric.Month),
			strconv.Itoa(metric.Day),
		})
		if err != nil {
			return err
		}
	}

	// accountId, accountName, s3 bucket, storage type, storage amount, year, month, day
	s3UsageFile, err := os.Create(fileName + "_s3_usage.csv")
	if err != nil {
		return err
	}

	s3UsageWriter := csv.NewWriter(s3UsageFile)
	defer s3UsageWriter.Flush()
	for _, metric := range pr.S3Usage {
		err = s3UsageWriter.Write([]string{
			metric.AccountId,
			metric.AccountName,
			metric.Bucket,
			metric.StorageType,
			fmt.Sprintf("%f", metric.Bytes),
			strconv.Itoa(metric.Year),
			strconv.Itoa(metric.Month),
			strconv.Itoa(metric.Day),
		})
		if err != nil {
			return err
		}
	}

	// accountId, accountName, service, serviceChargeType, service usage, USD, year, month, day
	serviceCostsFile, err := os.Create(fileName + "_service_cost.csv")
	if err != nil {
		return err
	}

	serviceCostsWriter := csv.NewWriter(serviceCostsFile)
	defer serviceCostsWriter.Flush()
	for _, metric := range pr.ServiceCost {
		err = serviceCostsWriter.Write([]string{
			metric.AccountId,
			metric.AccountName,
			metric.Service,
			metric.CostCategory,
			fmt.Sprintf("%f", metric.ServiceUsage),
			fmt.Sprintf("%f", metric.Cost),
			strconv.Itoa(metric.Year),
			strconv.Itoa(metric.Month),
			strconv.Itoa(metric.Day),
		})
		if err != nil {
			return err
		}
	}

	return nil
}
