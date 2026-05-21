import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CFN - REQ-10: trail enumerates assessed table by specific identifier', () => {
  it('passes (no finding) when EventSelectors DataResources Values list includes the assessed table identifier', () => {
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        OtherTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        DataEventsTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'trail-logs-bucket',
            IsLogging: true,
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: false,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    // After CFN preprocessing, !GetAtt AssessedTable.Arn becomes the logical id "AssessedTable",
                    // and !GetAtt OtherTable.Arn becomes "OtherTable". Both are listed explicitly.
                    Values: [
                      'arn:aws:dynamodb:us-east-1:123456789012:table/OtherTable',
                      'arn:aws:dynamodb:us-east-1:123456789012:table/AssessedTable',
                    ],
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Ddb002CfnAdapterFactory();
    const logicalId = 'AssessedTable';
    const resource = template.Resources![logicalId];

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(adapter.hasTrailCapturingDynamoDbDataEvents()).toBe(true);
    expect(result).toBeNull();
  });
});
