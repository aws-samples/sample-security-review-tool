import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 Terraform - REQ-01: DynamoDB data plane events must be captured by CloudTrail', () => {
  it('flags an aws_dynamodb_table when no aws_cloudtrail in the project configures DynamoDB data event logging', () => {
    const tableResource: TerraformResource = {
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

    // A CloudTrail exists but only configures S3 data events, not DynamoDB.
    const trailResource: TerraformResource = {
      address: 'aws_cloudtrail.some_trail',
      type: 'aws_cloudtrail',
      name: 'some_trail',
      values: {
        name: 'some-trail',
        s3_bucket_name: 'some-bucket',
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

    const allResources = [tableResource, trailResource];

    const context: TfContext = {
      projectName: 'test-project',
      resource: tableResource,
      allResources,
    };

    const factory = new Ddb002TfAdapterFactory();
    expect(factory.appliesTo('aws_dynamodb_table')).toBe(true);

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('aws_dynamodb_table.my_table');
    expect(result!.resourceType).toBe('aws_dynamodb_table');
    expect(result!.status).toBe('Open');
  });

  it('flags an aws_dynamodb_table when there is no aws_cloudtrail at all in the project', () => {
    const tableResource: TerraformResource = {
      address: 'aws_dynamodb_table.unaudited',
      type: 'aws_dynamodb_table',
      name: 'unaudited',
      values: {
        name: 'unaudited-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
        attribute: [{ name: 'id', type: 'S' }],
      },
    } as unknown as TerraformResource;

    const allResources = [tableResource];

    const context: TfContext = {
      projectName: 'test-project',
      resource: tableResource,
      allResources,
    };

    const factory = new Ddb002TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('aws_dynamodb_table.unaudited');
    expect(result!.resourceType).toBe('aws_dynamodb_table');
    expect(result!.status).toBe('Open');
  });
});
