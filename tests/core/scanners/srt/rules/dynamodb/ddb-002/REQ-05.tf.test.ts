import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 REQ-05 (Terraform)', () => {
  it('flags assessed table when an advanced event selector explicitly excludes it via equals listing other tables', () => {
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

    const otherTable: TerraformResource = {
      address: 'aws_dynamodb_table.other',
      type: 'aws_dynamodb_table',
      name: 'other',
      values: {
        name: 'other-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/other-table',
        billing_mode: 'PAY_PER_REQUEST',
        hash_key: 'id',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.data_events',
      type: 'aws_cloudtrail',
      name: 'data_events',
      values: {
        name: 'data-events-trail',
        enable_logging: true,
        s3_bucket_name: 'trail-bucket',
        advanced_event_selector: [
          {
            name: 'Log DynamoDB data events for select tables only',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
              {
                field: 'resources.ARN',
                // Explicitly only includes other-table; assessed-table excluded by selector condition
                equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/other-table'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [assessedTable, otherTable, trail];

    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('DDB-002');
    expect(result?.resourceName).toBe('aws_dynamodb_table.assessed');
    expect(result?.status).toBe('Open');
  });
});
