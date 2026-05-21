import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('DDB-002 Terraform - REQ-13: inconclusive ARN pattern match (lenient pass)', () => {
  it('passes when an event_selector data_resource references DynamoDB tables via an inconclusive value (null)', () => {
    // A null entry in the data_resource values array represents an ARN/pattern whose match
    // against the assessed table cannot be conclusively determined (e.g., a value not known
    // until apply-time). Per the resolved decision, the rule leniently treats this as covering
    // the table and passes.
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'my-assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-assessed-table',
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
            include_management_events: true,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                // Inconclusive value — cannot be determined at scan time
                values: [null],
              },
            ],
          },
        ],
      },
    } as TerraformResource;

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

  it('passes when an advanced_event_selector targets DynamoDB with a resources.ARN whose equals value is inconclusive', () => {
    // An object-typed entry in the equals array represents an unresolved/computed value
    // (e.g., a reference to another resource attribute not present in plan output).
    // The rule cannot conclusively determine whether the value matches the assessed table,
    // so it passes leniently.
    const assessedTable: TerraformResource = {
      address: 'aws_dynamodb_table.assessed',
      type: 'aws_dynamodb_table',
      name: 'assessed',
      values: {
        name: 'my-assessed-table',
        arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-assessed-table',
      },
    } as TerraformResource;

    const trail: TerraformResource = {
      address: 'aws_cloudtrail.trail',
      type: 'aws_cloudtrail',
      name: 'trail',
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
                // Object-typed entry — represents an unresolvable/computed pattern
                equals: [{ unresolved: 'computed-at-apply-time' }],
              },
            ],
          },
        ],
      },
    } as TerraformResource;

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
