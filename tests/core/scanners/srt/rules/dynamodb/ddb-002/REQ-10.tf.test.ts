import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 TF - REQ-10: trail enumerates assessed table by specific identifier', () => {
  it('passes (no finding) when event_selector data_resource values list includes the assessed table ARN', () => {
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
        hash_key: 'id',
        billing_mode: 'PAY_PER_REQUEST',
      },
    } as unknown as TerraformResource;

    const otherTable: TerraformResource = {
      address: 'aws_dynamodb_table.other',
      type: 'aws_dynamodb_table',
      name: 'other',
      values: {
        name: 'other-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/other-table',
        hash_key: 'id',
        billing_mode: 'PAY_PER_REQUEST',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.data_events',
      type: 'aws_cloudtrail',
      name: 'data_events',
      values: {
        name: 'data-events-trail',
        s3_bucket_name: 'trail-logs-bucket',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: false,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: [
                  'arn:aws:dynamodb:us-east-1:123456789012:table/other-table',
                  'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
                ],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const allResources = [assessedTable, otherTable, trail];

    const factory = new Ddb002TfAdapterFactory();
    expect(factory.appliesTo(assessedTable.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(adapter.hasTrailCapturingDynamoDbDataEvents()).toBe(true);
    expect(result).toBeNull();
  });
});
