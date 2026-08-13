import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildResource(encryptionConfiguration: Record<string, unknown>): TerraformResource {
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
              output_location: 's3://query-results/prefix/',
              encryption_configuration: [encryptionConfiguration],
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(encryptionConfiguration: Record<string, unknown>) {
  const resource = buildResource(encryptionConfiguration);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Ath001TfAdapterFactory().bind(context);
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-10 (Terraform): unsupported or empty query result encryption option', () => {
  // Primary behavior owned by this requirement: encryption settings present but the
  // option value is empty or not one of SSE_S3 / SSE_KMS / CSE_KMS -> flag.
  it('flags a workgroup whose encryption_option is an empty string', () => {
    const result = run({ encryption_option: '' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags a workgroup whose encryption_option is only whitespace', () => {
    expect(run({ encryption_option: '   ' })).not.toBeNull();
  });

  it('flags a workgroup whose encryption_option is outside the supported set', () => {
    expect(run({ encryption_option: 'AES256' })).not.toBeNull();
  });

  it('flags an unsupported encryption_option even when a kms_key_arn reference is supplied', () => {
    expect(run({
      encryption_option: 'SSE_S3_KMS',
      kms_key_arn: 'aws_kms_key.results',
    })).not.toBeNull();
  });

  it('flags a lowercase spelling of a supported option as unrecognized', () => {
    expect(run({ encryption_option: 'sse_kms', kms_key_arn: 'aws_kms_key.results' })).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the same settings block
  // with a supported option value instead of an unsupported one.
  it('does not flag a workgroup whose encryption_option is the supported SSE_S3 value', () => {
    expect(run({ encryption_option: 'SSE_S3' })).toBeNull();
  });
});
