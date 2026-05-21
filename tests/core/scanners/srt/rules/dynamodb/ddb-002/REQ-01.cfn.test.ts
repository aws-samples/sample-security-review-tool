import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CloudFormation - REQ-01: DynamoDB data plane events must be captured by CloudTrail', () => {
  it('flags a DynamoDB table when no CloudTrail trail in the template configures data event logging for DynamoDB', () => {
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
        // A CloudTrail exists but does NOT configure DynamoDB data events.
        SomeTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            IsLogging: true,
            S3BucketName: 'some-bucket',
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                // No DataResources for AWS::DynamoDB::Table
                DataResources: [
                  {
                    Type: 'AWS::S3::Object',
                    Values: ['arn:aws:s3:::some-bucket/'],
                  },
                ],
              },
            ],
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyTable,
      logicalId: 'MyTable',
    };

    const factory = new Ddb002CfnAdapterFactory();
    expect(factory.appliesTo('AWS::DynamoDB::Table')).toBe(true);

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('MyTable');
    expect(result!.resourceType).toBe('AWS::DynamoDB::Table');
    expect(result!.status).toBe('Open');
  });

  it('flags an AWS::DynamoDB::GlobalTable when no CloudTrail trail captures DynamoDB data events', () => {
    const template: Template = {
      Resources: {
        MyGlobalTable: {
          Type: 'AWS::DynamoDB::GlobalTable',
          Properties: {
            TableName: 'my-global-table',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
            Replicas: [{ Region: 'us-east-1' }],
          },
        },
        // No CloudTrail trail at all in the template.
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyGlobalTable,
      logicalId: 'MyGlobalTable',
    };

    const factory = new Ddb002CfnAdapterFactory();
    expect(factory.appliesTo('AWS::DynamoDB::GlobalTable')).toBe(true);

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('MyGlobalTable');
    expect(result!.resourceType).toBe('AWS::DynamoDB::GlobalTable');
    expect(result!.status).toBe('Open');
  });
});
