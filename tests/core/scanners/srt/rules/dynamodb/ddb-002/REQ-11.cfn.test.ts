import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (DDB-002): A CloudTrail trail covers the assessed DynamoDB table for data events
 * but is scoped to read-only events only OR write-only events only.
 *
 * Expected behavior: PASS
 * Rationale: any data event coverage (read-only or write-only) is sufficient.
 */

function buildContext(template: Template, logicalId: string): CfnContext {
  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources![logicalId],
    logicalId,
  };
}

function runControl(template: Template, logicalId: string) {
  const factory = new Ddb002CfnAdapterFactory();
  const ctx = buildContext(template, logicalId);
  const adapter = factory.bind(ctx);
  return ddb002Control.run(adapter, ctx);
}

describe('DDB-002 / REQ-11 (CloudFormation): trail covers DynamoDB data events scoped to read-only or write-only', () => {
  it('passes when a trail covers the assessed table with EventSelectors scoped to ReadOnly events only', () => {
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
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
        },
        ReadOnlyTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'TrailBucket',
            EventSelectors: [
              {
                ReadWriteType: 'ReadOnly',
                IncludeManagementEvents: false,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: ['arn:aws:dynamodb:us-east-1:123456789012:table/MyTable'],
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'MyTable');
    expect(result).toBeNull();
  });

  it('passes when a trail covers the assessed table with EventSelectors scoped to WriteOnly events only', () => {
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
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
        },
        WriteOnlyTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'TrailBucket',
            EventSelectors: [
              {
                ReadWriteType: 'WriteOnly',
                IncludeManagementEvents: false,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: ['arn:aws:dynamodb:us-east-1:123456789012:table/MyTable'],
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'MyTable');
    expect(result).toBeNull();
  });

  it('passes when AdvancedEventSelectors target the assessed table with a read-only scope (eventName != PutItem etc.)', () => {
    // Advanced event selectors can express read-only/write-only scoping via eventName field.
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
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
        },
        ReadOnlyAdvancedTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'TrailBucket',
            AdvancedEventSelectors: [
              {
                Name: 'DynamoDB read-only data events',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  {
                    Field: 'resources.ARN',
                    Equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/MyTable'],
                  },
                  { Field: 'readOnly', Equals: ['true'] },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'MyTable');
    expect(result).toBeNull();
  });

  it('passes when AdvancedEventSelectors target the assessed table with a write-only scope', () => {
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
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
        },
        WriteOnlyAdvancedTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'TrailBucket',
            AdvancedEventSelectors: [
              {
                Name: 'DynamoDB write-only data events',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  {
                    Field: 'resources.ARN',
                    Equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/MyTable'],
                  },
                  { Field: 'readOnly', Equals: ['false'] },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'MyTable');
    expect(result).toBeNull();
  });
});
