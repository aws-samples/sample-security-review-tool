import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ADDRESS = 'aws_athena_workgroup.analytics';

function workGroup(encryptionConfiguration: unknown): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: ADDRESS,
    values: {
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              output_location: 's3://query-results/',
              encryption_configuration: encryptionConfiguration,
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new Ath001TfAdapterFactory().bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-15 (Terraform): unresolvable query result encryption values', () => {
  // Primary behavior owned by this requirement: unresolvable values must not be flagged.
  it('passes when the encryption option is unknown at plan time', () => {
    const result = scan(workGroup([{ encryption_option: null }]));

    expect(result).toBeNull();
  });

  it('passes when the encryption configuration block itself is unknown at plan time', () => {
    const result = scan(workGroup(null));

    expect(result).toBeNull();
  });

  it('passes when the encryption option is unknown even though a KMS key is recorded', () => {
    const result = scan(workGroup([{ encryption_option: null, kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/abc' }]));

    expect(result).toBeNull();
  });

  it('passes when a KMS-based option specifies a KMS key that is unknown at plan time', () => {
    const result = scan(workGroup([{ encryption_option: 'SSE_KMS', kms_key_arn: null }]));

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict — the encryption option is
  // statically resolvable and is not one of the supported options, so it must be flagged.
  // (Primary behavior for that case belongs to the supported-option requirement.)
  it('flags when the encryption option resolves to a statically known unsupported value', () => {
    const result = scan(workGroup([{ encryption_option: 'AES256' }]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe(ADDRESS);
  });
});
