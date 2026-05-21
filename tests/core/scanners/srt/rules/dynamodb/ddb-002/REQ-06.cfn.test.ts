import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 REQ-06 (CloudFormation): unresolvable trail data event coverage passes (lenient match)', () => {
  it('passes when EventSelector DataResources.Values is an unresolved Fn::If (cannot be determined at analysis time)', () => {
    // The Values list is wrapped in Fn::If, which parseCfnTemplate leaves UNRESOLVED.
    // Per the lenient pattern matching decision, an undeterminable Values list is
    // assumed to cover the assessed table (i.e., treat unknown-array as "all").
    const template: Template = {
      Resources: {
        MyTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'my-table',
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        MyTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'cloudtrail-bucket',
            IsLogging: true,
            EventSelectors: [
              {
                IncludeManagementEvents: true,
                ReadWriteType: 'All',
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    // Unresolved intrinsic — analyzer cannot determine which tables are covered
                    Values: {
                      'Fn::If': [
                        'CaptureSpecificTables',
                        ['arn:aws:dynamodb:us-east-1:123456789012:table/some-other-table'],
                        ['arn:aws:dynamodb:us-east-1:123456789012:table/*'],
                      ],
                    },
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Ddb002CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyTable,
      logicalId: 'MyTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when AdvancedEventSelector resources.ARN Equals is an unresolved Fn::If', () => {
    const template: Template = {
      Resources: {
        MyTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'my-table',
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        MyTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'cloudtrail-bucket',
            IsLogging: true,
            AdvancedEventSelectors: [
              {
                Name: 'DynamoDB data events',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  {
                    Field: 'resources.ARN',
                    // Unresolved — cannot determine ARNs at analysis time
                    Equals: {
                      'Fn::If': [
                        'CaptureSpecificTables',
                        ['arn:aws:dynamodb:us-east-1:123456789012:table/some-other-table'],
                        ['arn:aws:dynamodb:us-east-1:123456789012:table/*'],
                      ],
                    },
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Ddb002CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyTable,
      logicalId: 'MyTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
