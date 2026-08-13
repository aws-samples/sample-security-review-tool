import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function buildWorkgroup(encryptionConfiguration: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: {
      name: 'analytics-workgroup',
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

function run(encryptionConfiguration: Record<string, unknown>) {
  const resource = buildWorkgroup(encryptionConfiguration);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 Terraform — SSE_KMS with a KMS key specified', () => {
  // Primary behavior owned by this requirement: SSE_KMS + kms_key_arn satisfies the rule.
  it('passes when encryption_option is SSE_KMS and a literal kms_key_arn ARN is provided', () => {
    const result = run({
      encryption_option: 'SSE_KMS',
      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    });

    expect(result).toBeNull();
  });

  it('passes when encryption_option is SSE_KMS and kms_key_arn references another resource', () => {
    // aws_kms_key.athena.arn collapses to the resource address string.
    const result = run({ encryption_option: 'SSE_KMS', kms_key_arn: 'aws_kms_key.athena' });

    expect(result).toBeNull();
  });

  // Opposite outcome: same supported KMS-based option, but the required key is not specified.
  it('flags SSE_KMS when kms_key_arn is present but empty, so no key is actually specified', () => {
    const result = run({ encryption_option: 'SSE_KMS', kms_key_arn: '' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });
});
