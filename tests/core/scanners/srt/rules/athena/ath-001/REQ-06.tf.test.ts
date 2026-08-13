import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildWorkgroup(encryptionConfiguration: Record<string, unknown>): TerraformResource {
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

function bind(encryptionConfiguration: Record<string, unknown>): { adapter: Ath001Adapter; context: TfContext } {
  const resource = buildWorkgroup(encryptionConfiguration);
  const context: TfContext = {
    projectName: 'analytics-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Ath001TfAdapterFactory().bind(context) as Ath001Adapter;
  return { adapter, context };
}

describe('ATH-001 Terraform - CSE_KMS with a KMS key', () => {
  // Primary behavior for this requirement: CSE_KMS plus a KMS key passes.
  it('passes when CSE_KMS encryption is configured with a literal KMS key ARN', () => {
    const { adapter, context } = bind({
      encryption_option: 'CSE_KMS',
      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    });

    expect(ath001Control.run(adapter, context)).toBeNull();
  });

  it('passes when CSE_KMS encryption references a KMS key resource', () => {
    // kms_key_arn = aws_kms_key.query.arn collapses to the resource address string.
    const { adapter, context } = bind({
      encryption_option: 'CSE_KMS',
      kms_key_arn: 'aws_kms_key.query',
    });

    expect(ath001Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: same supported option, but the KMS key required by KMS-based
  // options is absent, so the control must report a finding.
  it('flags CSE_KMS encryption when no KMS key is specified', () => {
    const { adapter, context } = bind({
      encryption_option: 'CSE_KMS',
    });

    const result = ath001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('ATH-001');
    expect(result!.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result!.resourceType).toBe('aws_athena_workgroup');
  });
});
