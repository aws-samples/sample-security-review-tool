import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 / REQ-09 (CloudFormation): wildcard/all-tables selector covers assessed table', () => {
  it('passes when EventSelectors use a table/* wildcard ARN that matches every DynamoDB table', () => {
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'assessed-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        DataEventsTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'trail-bucket',
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: ['arn:aws:dynamodb:us-east-1:123456789012:table/*'],
                  },
                ],
              },
            ],
          },
        },
      },
    };

    const factory = new Ddb002CfnAdapterFactory();
    const resource = template.Resources!.AssessedTable;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'AssessedTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
