import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function buildWorkGroup(encryptionConfiguration: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: {
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              output_location: 's3://query-results-bucket/results/',
              encryption_configuration: [encryptionConfiguration],
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 Terraform - CSE_KMS without a KMS key', () => {
  // Primary behavior owned by this requirement: CSE_KMS selected but no kms_key_arn specified.
  it('flags a workgroup using CSE_KMS with no kms_key_arn argument', () => {
    const result = run(buildWorkGroup({ encryption_option: 'CSE_KMS' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  it('flags a workgroup using CSE_KMS with an empty kms_key_arn value', () => {
    const result = run(buildWorkGroup({ encryption_option: 'CSE_KMS', kms_key_arn: '' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  // Opposite outcome: identical fixture except the required KMS key is present as a literal ARN.
  it('does not flag a workgroup using CSE_KMS when a literal kms_key_arn is provided', () => {
    const result = run(buildWorkGroup({
      encryption_option: 'CSE_KMS',
      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    }));

    expect(result).toBeNull();
  });

  // Reference form: kms_key_arn = aws_kms_key.athena.arn collapses to the key resource address.
  it('does not flag a workgroup using CSE_KMS when kms_key_arn references a KMS key resource', () => {
    const result = run(buildWorkGroup({
      encryption_option: 'CSE_KMS',
      kms_key_arn: 'aws_kms_key.athena',
    }));

    expect(result).toBeNull();
  });
});
