import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

function workgroup(configuration: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: {
      name: 'analytics',
      configuration: [configuration],
    },
  } as unknown as TerraformResource;
}

describe('ATH-001 (Terraform) - customer content encryption is not query result encryption', () => {
  // REQ-13 owns this behavior: a customer-managed key for Athena-managed customer
  // content / notebook data does NOT satisfy query result encryption.
  it('flags a workgroup with customer_content_encryption_configuration but no query result encryption', () => {
    const result = scan(workgroup({
      customer_content_encryption_configuration: [
        { kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/abc-123' },
      ],
      result_configuration: [
        { output_location: 's3://my-athena-results/' },
      ],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  // Opposite outcome: identical fixture except query result encryption IS specified.
  it('does not flag when the same workgroup also specifies query result encryption', () => {
    const result = scan(workgroup({
      customer_content_encryption_configuration: [
        { kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/abc-123' },
      ],
      result_configuration: [
        {
          output_location: 's3://my-athena-results/',
          encryption_configuration: [{ encryption_option: 'SSE_S3' }],
        },
      ],
    }));

    expect(result).toBeNull();
  });

  // Reference form: the customer content KMS key is wired via a resource reference,
  // collapsed by the plan reader to the key's address. Still no query result encryption.
  it('flags when the customer content KMS key is a resource reference and query results are unencrypted', () => {
    const result = scan(workgroup({
      customer_content_encryption_configuration: [
        { kms_key_arn: 'aws_kms_key.athena' },
      ],
      result_configuration: [
        { output_location: 's3://my-athena-results/' },
      ],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });
});
