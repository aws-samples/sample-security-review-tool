import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CloudFormation - REQ-13: inconclusive ARN pattern match (lenient pass)', () => {
  it('passes when a trail references DynamoDB tables via an unresolved ARN pattern (Fn::ImportValue) whose match cannot be conclusively determined', () => {
    // The Values entry is an unresolved intrinsic (Fn::ImportValue stays as an object after preprocessing).
    // The rule cannot conclusively determine whether this pattern covers the assessed table.
    // Per the resolved decision, the rule should leniently assume the pattern covers the table.
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'my-assessed-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
        },
        Trail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'TrailBucket',
            IsLogging: true,
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    // Unresolved intrinsic — represents an ARN pattern whose match is inconclusive
                    Values: [
                      { 'Fn::ImportValue': 'SomeOtherStack-TableArnPattern' },
                    ],
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

  it('passes when an advanced event selector references a resources.ARN value via Fn::If (inconclusive match)', () => {
    // The Equals entry contains an Fn::If which remains unresolved after preprocessing.
    // The rule cannot determine whether the resulting ARN matches the assessed table; lenient pass.
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'my-assessed-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
        },
        Trail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'TrailBucket',
            IsLogging: true,
            AdvancedEventSelectors: [
              {
                Name: 'DynamoDB data events',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  {
                    Field: 'resources.ARN',
                    Equals: [
                      {
                        'Fn::If': [
                          'UseSpecificTable',
                          'arn:aws:dynamodb:us-east-1:123456789012:table/some-other-table',
                          'arn:aws:dynamodb:us-east-1:123456789012:table/my-assessed-table',
                        ],
                      },
                    ],
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
