import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 REQ-05 (CloudFormation)', () => {
  it('flags assessed table when an advanced event selector explicitly excludes it via Equals listing other tables', () => {
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
        OtherTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'other-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'trail-bucket' },
        },
        DataEventsTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'trail-bucket',
            AdvancedEventSelectors: [
              {
                Name: 'Log DynamoDB data events for select tables only',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  {
                    Field: 'resources.ARN',
                    // Explicitly only includes OtherTable; AssessedTable excluded by selector condition
                    Equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/OtherTable'],
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
      resource: template.Resources!.AssessedTable,
      logicalId: 'AssessedTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('DDB-002');
    expect(result?.resourceName).toBe('AssessedTable');
    expect(result?.status).toBe('Open');
  });
});
