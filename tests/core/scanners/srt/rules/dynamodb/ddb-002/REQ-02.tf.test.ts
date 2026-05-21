import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 (Terraform) - REQ-02: trail logs data events only for non-DynamoDB resource types', () => {
  it('flags an aws_dynamodb_table when aws_cloudtrail event_selector captures only S3 object data events', () => {
    const table: TerraformResource = {
      address: 'aws_dynamodb_table.my_table',
      type: 'aws_dynamodb_table',
      name: 'my_table',
      values: {
        name: 'my-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
        attribute: [{ name: 'id', type: 'S' }],
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.my_trail',
      type: 'aws_cloudtrail',
      name: 'my_trail',
      values: {
        name: 'my-trail',
        s3_bucket_name: 'my-trail-bucket',
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::S3::Object',
                values: ['arn:aws:s3:::my-bucket/'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [table, trail];
    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: table,
      allResources,
    };
    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceType).toBe('aws_dynamodb_table');
    expect(result!.resourceName).toBe('aws_dynamodb_table.my_table');
    expect(result!.status).toBe('Open');
  });

  it('flags an aws_dynamodb_table when aws_cloudtrail advanced_event_selector captures only Lambda function data events', () => {
    const table: TerraformResource = {
      address: 'aws_dynamodb_table.my_table',
      type: 'aws_dynamodb_table',
      name: 'my_table',
      values: {
        name: 'my-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
        attribute: [{ name: 'id', type: 'S' }],
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.my_trail',
      type: 'aws_cloudtrail',
      name: 'my_trail',
      values: {
        name: 'my-trail',
        s3_bucket_name: 'my-trail-bucket',
        advanced_event_selector: [
          {
            name: 'Log Lambda data events only',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::Lambda::Function'] },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [table, trail];
    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: table,
      allResources,
    };
    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceType).toBe('aws_dynamodb_table');
    expect(result!.resourceName).toBe('aws_dynamodb_table.my_table');
    expect(result!.status).toBe('Open');
  });
});
