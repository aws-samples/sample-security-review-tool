import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 CloudFormation - REQ-12: single-region trail with matching selectors, table region differs/undeterminable', () => {
  it('passes when a single-region trail covers the assessed table via DataResources, regardless of region', () => {
    // Trail is single-region (IsMultiRegionTrail: false) and explicitly in us-west-2.
    // Assessed table has no region info in the template (region not determinable).
    // Per resolved decision: region matching is out of scope; selectors matching is sufficient.
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'AssessedTable',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        TrailBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        SingleRegionTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'TrailBucket',
            IsLogging: true,
            IsMultiRegionTrail: false,
            // Single-region trail explicitly indicating a different region than the table.
            // (Region matching is out of scope; this should not affect outcome.)
            EventSelectors: [
              {
                ReadWriteType: 'All',
                IncludeManagementEvents: true,
                DataResources: [
                  {
                    Type: 'AWS::DynamoDB::Table',
                    Values: ['arn:aws:dynamodb:us-west-2:123456789012:table/AssessedTable'],
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const factory = new Ddb002CfnAdapterFactory();
    const resource = template.Resources!.AssessedTable;
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'AssessedTable',
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a single-region trail covers the table via AdvancedEventSelectors, with region undeterminable from template', () => {
    const template: Template = {
      Resources: {
        AssessedTable: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            TableName: 'AssessedTable',
            AttributeDefinitions: [{ AttributeName: 'id', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'id', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
          },
        },
        SingleRegionTrail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: {
            S3BucketName: 'some-bucket',
            IsLogging: true,
            IsMultiRegionTrail: false,
            AdvancedEventSelectors: [
              {
                Name: 'Capture DynamoDB data events',
                FieldSelectors: [
                  { Field: 'eventCategory', Equals: ['Data'] },
                  { Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] },
                  {
                    Field: 'resources.ARN',
                    Equals: ['arn:aws:dynamodb:eu-west-1:123456789012:table/AssessedTable'],
                  },
                ],
              },
            ],
          },
        },
      },
    } as unknown as Template;

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

    expect(result).toBeNull();
  });
});
