import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 REQ-04 (CloudFormation): trail enumerates DynamoDB tables individually and assessed table is not listed', () => {
  it('flags the assessed table when a trail lists other DynamoDB tables individually via EventSelectors but not the assessed one', () => {
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
        OtherTableA: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        OtherTableB: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
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
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    // Per-resource enumeration: only OtherTableA and OtherTableB are listed
                    Values: ['OtherTableA', 'OtherTableB'],
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

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('AssessedTable');
    expect(result!.status).toBe('Open');
  });

  it('flags the assessed table when a trail lists other DynamoDB tables individually via AdvancedEventSelectors but not the assessed one', () => {
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
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        Trail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'TrailBucket',
            IsLogging: true,
            AdvancedEventSelectors: [
              {
                Name: 'Log DynamoDB data events for specific tables',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  // Per-resource enumeration via resources.ARN: only OtherTable is listed
                  { Field: 'resources.ARN', Equals: ['OtherTable'] },
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

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('AssessedTable');
  });
});
