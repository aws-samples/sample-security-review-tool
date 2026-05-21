import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 Terraform - REQ-12: single-region trail with matching selectors, table region differs/undeterminable', () => {
  it('passes when a single-region trail covers the assessed table via event_selector, regardless of region', () => {
    // Trail is single-region (is_multi_region_trail = false) located in us-west-2.
    // Assessed table values include an ARN in us-east-1 (regions differ).
    // Per resolved decision: region matching is out of scope.
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
        billing_mode: 'PAY_PER_REQUEST',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.single_region',
      type: 'aws_cloudtrail',
      name: 'single_region',
      values: {
        name: 'single-region-trail',
        s3_bucket_name: 'some-bucket',
        is_multi_region_trail: false,
        enable_logging: true,
        // Trail's implicit region (us-west-2) differs from the table's ARN region (us-east-1).
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: ['arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Ddb002TfAdapterFactory();
    expect(factory.appliesTo(assessedTable.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: assessedTable,
      allResources: [assessedTable, trail],
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a single-region trail covers the table via advanced_event_selector and the table region is not determinable', () => {
    // Assessed table has no `arn` attribute — region is not determinable from the template.
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'assessed-table',
        billing_mode: 'PAY_PER_REQUEST',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.single_region',
      type: 'aws_cloudtrail',
      name: 'single_region',
      values: {
        name: 'single-region-trail',
        s3_bucket_name: 'some-bucket',
        is_multi_region_trail: false,
        enable_logging: true,
        advanced_event_selector: [
          {
            name: 'Capture DynamoDB data events',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
              {
                field: 'resources.ARN',
                equals: ['arn:aws:dynamodb:ap-southeast-2:123456789012:table/assessed-table'],
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
