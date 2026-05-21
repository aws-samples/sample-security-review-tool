import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CloudFormation - REQ-07: One trail covers DynamoDB, another covers only management/unrelated data events', () => {
  it('passes when at least one trail captures DynamoDB data events for the assessed table, even though another trail does not', () => {
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'AssessedTable',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        // Trail 1: Covers DynamoDB data events for the assessed table
        DynamoDbDataEventsTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'my-trail-bucket',
            IsLogging: true,
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: ['arn:aws:dynamodb:us-east-1:123456789012:table/AssessedTable'],
                  },
                ],
              },
            ],
          },
        },
        // Trail 2: Only management events + unrelated data events (S3)
        ManagementOnlyTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'mgmt-trail-bucket',
            IsLogging: true,
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::S3::Object',
                    Values: ['arn:aws:s3:::some-bucket/'],
                  },
                ],
              },
            ],
          },
        },
      },
    };

    const factory = new Ddb002CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.AssessedTable,
      logicalId: 'AssessedTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
