import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 REQ-04 (Terraform): trail enumerates DynamoDB tables individually and assessed table is not listed', () => {
  it('flags the assessed table when a trail lists other DynamoDB tables individually via event_selector but not the assessed one', () => {
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    const otherTableA: TerraformResource = {
      address: 'aws_dynamodb_table.other_a',
      type: 'aws_dynamodb_table',
      name: 'other_a',
      values: {
        name: 'other-table-a',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/other-table-a',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    const otherTableB: TerraformResource = {
      address: 'aws_dynamodb_table.other_b',
      type: 'aws_dynamodb_table',
      name: 'other_b',
      values: {
        name: 'other-table-b',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/other-table-b',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.trail',
      type: 'aws_cloudtrail',
      name: 'trail',
      values: {
        name: 'my-trail',
        s3_bucket_name: 'my-trail-bucket',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                // Per-resource enumeration: only the other tables' ARNs are listed
                values: [
                  'arn:aws:dynamodb:us-east-1:123456789012:table/other-table-a',
                  'arn:aws:dynamodb:us-east-1:123456789012:table/other-table-b',
                ],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [assessedTable, otherTableA, otherTableB, trail];

    const factory = new Ddb002TfAdapterFactory();
    expect(factory.appliesTo(assessedTable.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('aws_dynamodb_table.assessed');
    expect(result!.status).toBe('Open');
  });

  it('flags the assessed table when a trail lists other DynamoDB tables individually via advanced_event_selector but not the assessed one', () => {
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
      },
    } as unknown as TerraformResource;

    const otherTable: TerraformResource = {
      address: 'aws_dynamodb_table.other',
      type: 'aws_dynamodb_table',
      name: 'other',
      values: {
        name: 'other-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/other-table',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.trail',
      type: 'aws_cloudtrail',
      name: 'trail',
      values: {
        name: 'my-trail',
        s3_bucket_name: 'my-trail-bucket',
        enable_logging: true,
        advanced_event_selector: [
          {
            name: 'Log DynamoDB data events for specific tables',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
              // Per-resource enumeration: only the other table's ARN is listed
              {
                field: 'resources.ARN',
                equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/other-table'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [assessedTable, otherTable, trail];

    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('DDB-002');
    expect(result!.resourceName).toBe('aws_dynamodb_table.assessed');
  });
});
