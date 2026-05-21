import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CloudFormation - REQ-08: Empty Values list in DynamoDB data event selector', () => {
  it('flags the table when the trail event selector for DynamoDB data events has an empty Values list', () => {
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
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        Trail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'TrailBucket',
            IsLogging: true,
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: false,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: [],
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

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('AssessedTable');
    expect(result!.status).toBe('Open');
  });
});
