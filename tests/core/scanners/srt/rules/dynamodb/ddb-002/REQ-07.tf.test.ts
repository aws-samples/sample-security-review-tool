import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 Terraform - REQ-07: One trail covers DynamoDB, another covers only management/unrelated data events', () => {
  it('passes when at least one trail captures DynamoDB data events for the assessed table, even though another trail does not', () => {
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'AssessedTable',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/AssessedTable',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    // Trail 1: Covers DynamoDB data events for the assessed table
    const dynamoDbTrail: TerraformResource = {
      address: 'aws_cloudtrail.dynamodb_trail',
      type: 'aws_cloudtrail',
      name: 'dynamodb_trail',
      values: {
        name: 'dynamodb-trail',
        s3_bucket_name: 'my-trail-bucket',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: ['arn:aws:dynamodb:us-east-1:123456789012:table/AssessedTable'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    // Trail 2: Only management events + unrelated data events (S3)
    const managementOnlyTrail: TerraformResource = {
      address: 'aws_cloudtrail.mgmt_trail',
      type: 'aws_cloudtrail',
      name: 'mgmt_trail',
      values: {
        name: 'mgmt-trail',
        s3_bucket_name: 'mgmt-trail-bucket',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::S3::Object',
                values: ['arn:aws:s3:::some-bucket/'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [assessedTable, dynamoDbTrail, managementOnlyTrail];

    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
