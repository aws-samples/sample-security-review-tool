import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CloudFormation REQ-03: Trail captures DynamoDB data events but logging is explicitly disabled', () => {
  it('flags the DynamoDB table when the capturing trail has IsLogging=false (basic event selectors)', () => {
    const template: Template = {
      Resources: {
        MyTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'my-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        DisabledTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            TrailName: 'disabled-trail',
            S3BucketName: 'audit-bucket',
            IsLogging: false,
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: ['arn:aws:dynamodb'],
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Ddb002CfnAdapterFactory();
    const tableResource = template.Resources!.MyTable;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: tableResource,
      logicalId: 'MyTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('DDB-002');
    expect(result?.resourceName).toBe('MyTable');
    expect(result?.resourceType).toBe('AWS::DynamoDB::Table');
    expect(result?.status).toBe('Open');
  });

  it('flags the DynamoDB table when the capturing trail (advanced event selectors) has IsLogging=false', () => {
    const template: Template = {
      Resources: {
        MyTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'my-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        DisabledAdvancedTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            TrailName: 'disabled-advanced-trail',
            S3BucketName: 'audit-bucket',
            IsLogging: false,
            AdvancedEventSelectors: [
              {
                Name: 'DynamoDB data events',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Ddb002CfnAdapterFactory();
    const tableResource = template.Resources!.MyTable;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: tableResource,
      logicalId: 'MyTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('DDB-002');
    expect(result?.resourceName).toBe('MyTable');
  });
});
