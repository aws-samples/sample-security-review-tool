import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 Terraform REQ-03: Trail captures DynamoDB data events but logging is explicitly disabled', () => {
  it('flags the DynamoDB table when the capturing trail has enable_logging=false (basic event_selector)', () => {
    const tableResource: TerraformResource = {
      address: 'aws_dynamodb_table.my_table',
      type: 'aws_dynamodb_table',
      name: 'my_table',
      values: {
        name: 'my-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    const trailResource: TerraformResource = {
      address: 'aws_cloudtrail.disabled_trail',
      type: 'aws_cloudtrail',
      name: 'disabled_trail',
      values: {
        name: 'disabled-trail',
        s3_bucket_name: 'audit-bucket',
        enable_logging: false,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: ['arn:aws:dynamodb'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [tableResource, trailResource];
    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: tableResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('DDB-002');
    expect(result?.resourceName).toBe('aws_dynamodb_table.my_table');
    expect(result?.resourceType).toBe('aws_dynamodb_table');
    expect(result?.status).toBe('Open');
  });

  it('flags the DynamoDB table when the capturing trail (advanced_event_selector) has enable_logging=false', () => {
    const tableResource: TerraformResource = {
      address: 'aws_dynamodb_table.my_table',
      type: 'aws_dynamodb_table',
      name: 'my_table',
      values: {
        name: 'my-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    const trailResource: TerraformResource = {
      address: 'aws_cloudtrail.disabled_advanced_trail',
      type: 'aws_cloudtrail',
      name: 'disabled_advanced_trail',
      values: {
        name: 'disabled-advanced-trail',
        s3_bucket_name: 'audit-bucket',
        enable_logging: false,
        advanced_event_selector: [
          {
            name: 'DynamoDB data events',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [tableResource, trailResource];
    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: tableResource,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('DDB-002');
    expect(result?.resourceName).toBe('aws_dynamodb_table.my_table');
  });
});
