import { describe, it, expect } from 'vitest';
import { ddb002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.control.js';
import { Ddb002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/dynamodb/ddb-002/ddb-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (DDB-002): A CloudTrail trail covers the assessed DynamoDB table for data events
 * but is scoped to read-only events only OR write-only events only.
 *
 * Expected behavior: PASS
 * Rationale: any data event coverage (read-only or write-only) is sufficient.
 */

function runControl(assessed: TerraformResource, allResources: TerraformResource[]) {
  const factory = new Ddb002TfAdapterFactory();
  const ctx: TfContext = {
    projectName: 'test-project',
    resource: assessed,
    allResources,
  };
  const adapter = factory.bind(ctx);
  return ddb002Control.run(adapter, ctx);
}

describe('DDB-002 / REQ-11 (Terraform): trail covers DynamoDB data events scoped to read-only or write-only', () => {
  it('passes when a trail covers the assessed table with event_selector scoped to ReadOnly events only', () => {
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
      address: 'aws_cloudtrail.read_only_trail',
      type: 'aws_cloudtrail',
      name: 'read_only_trail',
      values: {
        name: 'read-only-trail',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'ReadOnly',
            include_management_events: false,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: ['arn:aws:dynamodb:us-east-1:123456789012:table/my-table'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runControl(table, [table, trail]);
    expect(result).toBeNull();
  });

  it('passes when a trail covers the assessed table with event_selector scoped to WriteOnly events only', () => {
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
      address: 'aws_cloudtrail.write_only_trail',
      type: 'aws_cloudtrail',
      name: 'write_only_trail',
      values: {
        name: 'write-only-trail',
        enable_logging: true,
        event_selector: [
          {
            read_write_type: 'WriteOnly',
            include_management_events: false,
            data_resource: [
              {
                type: 'AWS::DynamoDB::Table',
                values: ['arn:aws:dynamodb:us-east-1:123456789012:table/my-table'],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runControl(table, [table, trail]);
    expect(result).toBeNull();
  });

  it('passes when advanced_event_selector targets the assessed table with a read-only scope', () => {
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
      address: 'aws_cloudtrail.advanced_read_only',
      type: 'aws_cloudtrail',
      name: 'advanced_read_only',
      values: {
        name: 'advanced-read-only-trail',
        enable_logging: true,
        advanced_event_selector: [
          {
            name: 'DynamoDB read-only data events',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
              {
                field: 'resources.ARN',
                equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/my-table'],
              },
              { field: 'readOnly', equals: ['true'] },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runControl(table, [table, trail]);
    expect(result).toBeNull();
  });

  it('passes when advanced_event_selector targets the assessed table with a write-only scope', () => {
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
      address: 'aws_cloudtrail.advanced_write_only',
      type: 'aws_cloudtrail',
      name: 'advanced_write_only',
      values: {
        name: 'advanced-write-only-trail',
        enable_logging: true,
        advanced_event_selector: [
          {
            name: 'DynamoDB write-only data events',
            field_selector: [
              { field: 'eventCategory', equals: ['Data'] },
              { field: 'resources.type', equals: ['AWS::DynamoDB::Table'] },
              {
                field: 'resources.ARN',
                equals: ['arn:aws:dynamodb:us-east-1:123456789012:table/my-table'],
              },
              { field: 'readOnly', equals: ['false'] },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = runControl(table, [table, trail]);
    expect(result).toBeNull();
  });
});
