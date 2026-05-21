import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 Terraform - REQ-08: Empty values list in DynamoDB data event selector', () => {
  it('flags the table when the trail event_selector for DynamoDB data events has an empty values list', () => {
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/assessed-table',
      },
    } as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.trail',
      type: 'aws_cloudtrail',
      name: 'trail',
      values: {
        name: 'my-trail',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'All',
            include_management_events: false,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: [],
              },
            ],
          },
        ],
      },
    } as TerraformResource;

    const allResources = [assessedTable, trail];

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
    expect(result!.status).toBe('Open');
  });
});
