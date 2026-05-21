import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 / REQ-09 (Terraform): wildcard/all-tables selector covers assessed table', () => {
  it('passes when event_selector uses a table/* wildcard ARN that matches every DynamoDB table', () => {
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        name: 'assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
        billing_mode: 'PAY_PER_REQUEST',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.data_events',
      type: 'aws_cloudtrail',
      name: 'data_events',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        name: 'data-events-trail',
        s3_bucket_name: 'trail-bucket',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: ['arn:aws:dynamodb:us-east-1:123456789012:table/*'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources: [assessedTable, trail],
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
