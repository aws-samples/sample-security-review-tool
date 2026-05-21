import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 REQ-06 (Terraform): unresolvable trail data event coverage passes (lenient match)', () => {
  it('passes when event_selector data_resource.values is unknown (null) at plan time', () => {
    // In a Terraform plan, an unknown value is represented as null (not yet computed).
    // The analyzer cannot determine which tables are covered, so per the lenient
    // pattern matching decision, coverage is assumed.
    const table: TerraformResource = {
      address: 'aws_dynamodb_table.my_table',
      type: 'aws_dynamodb_table',
      name: 'my_table',
      values: {
        name: 'my-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.my_trail',
      type: 'aws_cloudtrail',
      name: 'my_trail',
      values: {
        name: 'my-trail',
        enable_logging: true,
        event_selector: [
          {
            include_management_events: true,
            read_write_type: 'All',
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                // Unknown at plan time — values list cannot be resolved
                values: null,
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: table,
      allResources: [table, trail],
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when advanced_event_selector resources.ARN equals is unknown (null) at plan time', () => {
    const table: TerraformResource = {
      address: 'aws_dynamodb_table.my_table',
      type: 'aws_dynamodb_table',
      name: 'my_table',
      values: {
        name: 'my-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
      },
    } as unknown as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.my_trail',
      type: 'aws_cloudtrail',
      name: 'my_trail',
      values: {
        name: 'my-trail',
        enable_logging: true,
        advanced_event_selector: [
          {
            name: 'DynamoDB data events',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
              {
                field: 'resources.ARN',
                // Unknown at plan time — analyzer cannot determine ARNs
                equals: null,
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Ddb002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: table,
      allResources: [table, trail],
    };

    const adapter = factory.bind(context);
    const result = ddb002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
