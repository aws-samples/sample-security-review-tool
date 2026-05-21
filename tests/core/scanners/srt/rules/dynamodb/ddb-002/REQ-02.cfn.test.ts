import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 (CloudFormation) - REQ-02: trail logs data events only for non-DynamoDB resource types', () => {
  it('flags a DynamoDB::Table when CloudTrail EventSelectors capture only S3 object data events', () => {
    const template = {
      Resources: {
        MyTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        MyTrail: {
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
                    Type: 'AWS::S3::Object',
                    Values: ['arn:aws:s3:::my-bucket/'],
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

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('MyTable');
    expect(result!.resourceType).toBe('AWS::DynamoDB::Table');
    expect(result!.status).toBe('Open');
  });

  it('flags a DynamoDB::GlobalTable when CloudTrail AdvancedEventSelectors capture only Lambda function data events', () => {
    const template = {
      Resources: {
        MyGlobalTable: {
          Type: 'AWS::DynamoDB::GlobalTable',
          Properties: {
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            BillingMode: 'PAY_PER_REQUEST',
            Replicas: [{ Region: 'us-east-1' }],
          },
        },
        MyTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'my-trail-bucket',
            IsLogging: true,
            AdvancedEventSelectors: [
              {
                Name: 'Log Lambda data events only',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::Lambda::Function'] },
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
      resource: template.Resources!.MyGlobalTable,
      logicalId: 'MyGlobalTable',
    };
    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('MyGlobalTable');
    expect(result!.resourceType).toBe('AWS::DynamoDB::GlobalTable');
    expect(result!.status).toBe('Open');
  });
});
