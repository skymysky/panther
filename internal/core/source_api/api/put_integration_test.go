package api

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/api/lambda/source/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	awspoller "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/internal/core/source_api/ddb/modelstest"
)

// Mocks

// mockSQSClient mocks API calls to SQS.
type mockSQSClient struct {
	sqsiface.SQSAPI
	mock.Mock
}

func (client *mockSQSClient) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*sqs.SendMessageBatchOutput), args.Error(1)
}

func (client *mockSQSClient) SetQueueAttributes(input *sqs.SetQueueAttributesInput) (*sqs.SetQueueAttributesOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*sqs.SetQueueAttributesOutput), args.Error(1)
}

func (client *mockSQSClient) GetQueueAttributes(input *sqs.GetQueueAttributesInput) (*sqs.GetQueueAttributesOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*sqs.GetQueueAttributesOutput), args.Error(1)
}

func generateMockSQSBatchInputOutput(integrations []*models.SourceIntegrationMetadata) (
	*sqs.SendMessageBatchInput, *sqs.SendMessageBatchOutput, error) {

	// Setup input/output
	var sqsEntries []*sqs.SendMessageBatchRequestEntry
	var err error
	in := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String("test-url"),
	}
	out := &sqs.SendMessageBatchOutput{
		Successful: []*sqs.SendMessageBatchResultEntry{
			{
				Id:               integrations[0].IntegrationID,
				MessageId:        integrations[0].IntegrationID,
				MD5OfMessageBody: aws.String("f6255bb01c648fe967714d52a89e8e9c"),
			},
		},
	}

	// Generate all messages for scans
	for _, integration := range integrations {
		for resourceType := range awspoller.ServicePollers {
			scanMsg := &pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					{
						AWSAccountID:  integration.AWSAccountID,
						IntegrationID: integration.IntegrationID,
						ResourceType:  aws.String(resourceType),
					},
				},
			}

			var messageBodyBytes []byte
			messageBodyBytes, err = jsoniter.Marshal(scanMsg)
			if err != nil {
				break
			}

			sqsEntries = append(sqsEntries, &sqs.SendMessageBatchRequestEntry{
				Id:          integration.IntegrationID,
				MessageBody: aws.String(string(messageBodyBytes)),
			})
		}
	}

	in.Entries = sqsEntries
	return in, out, err
}

// Unit Tests

func TestAddToSnapshotQueue(t *testing.T) {
	snapshotPollersQueueURL = "test-url"
	testIntegrations := []*models.SourceIntegrationMetadata{
		{
			AWSAccountID:     aws.String(testAccountID),
			CreatedAtTime:    aws.Time(time.Time{}),
			CreatedBy:        aws.String("Bobert"),
			IntegrationID:    aws.String(testIntegrationID),
			IntegrationLabel: aws.String("BobertTest"),
			IntegrationType:  aws.String("aws-scan"),
			ScanEnabled:      aws.Bool(true),
			ScanIntervalMins: aws.Int(60),
		},
	}

	sqsIn, sqsOut, err := generateMockSQSBatchInputOutput(testIntegrations)
	require.NoError(t, err)

	mockSQS := &mockSQSClient{}
	// It's non trivial to mock when the order of a slice is not promised
	mockSQS.On("SendMessageBatch", mock.Anything).Return(sqsOut, nil)
	SQSClient = mockSQS

	err = ScanAllResources(testIntegrations)

	require.NoError(t, err)
	// Check that there is one message per service
	assert.Len(t, sqsIn.Entries, len(awspoller.ServicePollers))
}

func TestPutIntegration(t *testing.T) {
	mockSQS := &mockSQSClient{}
	mockSQS.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil)
	SQSClient = mockSQS
	db = &ddb.DDB{Client: &modelstest.MockDDBClient{TestErr: false}, TableName: "test"}
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (bool, error) { return true, nil }

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:     aws.String(testAccountID),
				IntegrationLabel: aws.String(testIntegrationLabel),
				IntegrationType:  aws.String(testIntegrationType),
				ScanEnabled:      aws.Bool(true),
				ScanIntervalMins: aws.Int(60),
				UserID:           aws.String(testUserID),
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, out)
}

func TestPutIntegrationExists(t *testing.T) {
	mockSQS := &mockSQSClient{}
	mockSQS.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil)
	SQSClient = mockSQS

	db = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			MockScanAttributes: []map[string]*dynamodb.AttributeValue{
				{
					"awsAccountId":    {S: aws.String(testAccountID)},
					"integrationType": {S: aws.String(testIntegrationType)},
				},
			},
			TestErr: false,
		},
		TableName: "test",
	}

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:     aws.String(testAccountID),
				IntegrationLabel: aws.String(testIntegrationLabel),
				IntegrationType:  aws.String(testIntegrationType),
				ScanEnabled:      aws.Bool(true),
				ScanIntervalMins: aws.Int(60),
				UserID:           aws.String(testUserID),
			},
		},
	})
	require.NoError(t, err)
	require.Empty(t, out) // should do nothing
}

func TestPutIntegrationValidInput(t *testing.T) {
	validator, err := models.Validator()
	require.NoError(t, err)
	assert.NoError(t, validator.Struct(&models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:     aws.String(testAccountID),
				IntegrationLabel: aws.String(testIntegrationLabel),
				IntegrationType:  aws.String(testIntegrationType),
				ScanEnabled:      aws.Bool(true),
				ScanIntervalMins: aws.Int(60),
				UserID:           aws.String(testUserID),
			},
		},
	}))
}

func TestPutIntegrationInvalidInput(t *testing.T) {
	validator, err := models.Validator()
	require.NoError(t, err)
	assert.Error(t, validator.Struct(&models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				// Long account ID
				AWSAccountID: aws.String("11111111111111"),
				ScanEnabled:  aws.Bool(true),
				// Invalid integration type
				IntegrationType: aws.String("type-that-does-not-exist"),
			},
		},
	}))
}

func TestPutIntegrationDatabaseError(t *testing.T) {
	in := &models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:     aws.String(testAccountID),
				IntegrationLabel: aws.String(testIntegrationLabel),
				IntegrationType:  aws.String(testIntegrationType),
				ScanEnabled:      aws.Bool(true),
				UserID:           aws.String(testUserID),
			},
		},
	}

	db = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			TestErr: true,
		},
		TableName: "test",
	}

	mockSQS := &mockSQSClient{}
	SQSClient = mockSQS
	mockSQS.On("AddPermission", mock.Anything).Return(&sqs.AddPermissionOutput{}, nil)
	// RemoveRermission will be called to remove the permission that was added previously
	// This is done as part of rollback process to bring the system in a consistent state
	mockSQS.On("RemovePermission", mock.Anything).Return(&sqs.RemovePermissionOutput{}, nil)

	out, err := apiTest.PutIntegration(in)
	assert.Error(t, err)
	assert.Empty(t, out)
}

func TestPutIntegrationDatabaseErrorRecoveryFails(t *testing.T) {
	// Used to capture logs for unit testing purposes
	core, recordedLogs := observer.New(zapcore.ErrorLevel)
	zap.ReplaceGlobals(zap.New(core))

	in := &models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:     aws.String(testAccountID),
				IntegrationLabel: aws.String(testIntegrationLabel),
				IntegrationType:  aws.String(testIntegrationType),
				ScanEnabled:      aws.Bool(true),
				UserID:           aws.String(testUserID),
			},
		},
	}

	db = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			TestErr: true,
		},
		TableName: "test",
	}

	mockSQS := &mockSQSClient{}
	SQSClient = mockSQS
	mockSQS.On("AddPermission", mock.Anything).Return(&sqs.AddPermissionOutput{}, nil)
	// RemoveRermission will be called to remove the permission that was added previously
	// This is done as part of rollback process to bring the system in a consistent state
	mockSQS.On("RemovePermission", mock.Anything).Return(&sqs.RemovePermissionOutput{}, errors.New("error"))

	out, err := apiTest.PutIntegration(in)
	require.Error(t, err)
	require.Empty(t, out)

	errorLog := recordedLogs.FilterMessage("failed to remove SQS permission for integration." +
		" SQS queue has additional permissions that have to be removed manually")
	require.NotNil(t, errorLog)
}

func TestPutLogIntegrationUpdateSqsQueuePermissions(t *testing.T) {
	db = &ddb.DDB{Client: &modelstest.MockDDBClient{TestErr: false}, TableName: "test"}
	mockSQS := &mockSQSClient{}
	SQSClient = mockSQS
	logProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	expectedGetQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{"Policy"}),
		QueueUrl:       aws.String(logProcessorQueueURL),
	}
	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{})
	mockSQS.On("GetQueueAttributes", expectedGetQueueAttributesInput).
		Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil)
	expectedAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	expectedSetAttributes := &sqs.SetQueueAttributesInput{
		Attributes: expectedAttributes,
		QueueUrl:   aws.String(logProcessorQueueURL),
	}
	mockSQS.On("SetQueueAttributes", expectedSetAttributes).Return(&sqs.SetQueueAttributesOutput{}, nil)

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:    aws.String(testAccountID),
				IntegrationType: aws.String(models.IntegrationTypeAWS3),
				UserID:          aws.String(testUserID),
				S3Buckets:       aws.StringSlice([]string{"bucket"}),
				KmsKeys:         aws.StringSlice([]string{"keyarns"}),
			},
		},
	})

	require.NoError(t, err)
	require.NotEmpty(t, out)
}

func TestPutLogIntegrationUpdateSqsQueuePermissionsFailure(t *testing.T) {
	db = &ddb.DDB{Client: &modelstest.MockDDBClient{TestErr: false}, TableName: "test"}
	mockSQS := &mockSQSClient{}
	SQSClient = mockSQS
	logProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	mockSQS.On("GetQueueAttributes", mock.Anything).Return(&sqs.GetQueueAttributesOutput{}, errors.New("error"))

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		Integrations: []*models.PutIntegrationSettings{
			{
				AWSAccountID:    aws.String(testAccountID),
				IntegrationType: aws.String(models.IntegrationTypeAWS3),
				UserID:          aws.String(testUserID),
				S3Buckets:       aws.StringSlice([]string{"bucket"}),
				KmsKeys:         aws.StringSlice([]string{"keyarns"}),
			},
		},
	})
	require.Error(t, err)
	require.Empty(t, out)
}
