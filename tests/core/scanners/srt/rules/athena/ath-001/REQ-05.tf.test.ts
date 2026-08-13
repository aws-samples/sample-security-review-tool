import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_athena_workgroup';
const ADDRESS = 'aws_athena_workgroup.analytics';

function buildResource(encryptionConfiguration: Record<string, unknown>): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'analytics',
    address: ADDRESS,
    values: {
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              output_location: 's3://analytics-results/queries/',
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
  const context: TfContext = { projectName: 'analytics-project', resource, allResources: [resource] };
  const adapter = new Ath001TfAdapterFactory().bind(context);
  return ath001Control.run(adapter, context);
}

describe('ATH-001 Terraform - SSE_KMS without a KMS key (REQ-05)', () => {
  it('flags a workgroup that selects SSE_KMS but supplies no kms_key_arn', () => {
    // Primary behavior owned by this requirement: KMS-based encryption requires a key.
    const result = run({ encryption_option: 'SSE_KMS' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.issue).toMatch(/KMS key/i);
  });

  it('flags a workgroup that selects SSE_KMS with an empty kms_key_arn value', () => {
    const result = run({ encryption_option: 'SSE_KMS', kms_key_arn: '' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.issue).toMatch(/KMS key/i);
  });

  it('does NOT flag the same workgroup once a literal kms_key_arn ARN is supplied (opposite outcome)', () => {
    const result = run({
      encryption_option: 'SSE_KMS',
      kms_key_arn: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    });

    expect(result).toBeNull();
  });

  it('does NOT flag the same workgroup when kms_key_arn is a reference to a KMS key resource (opposite outcome)', () => {
    // Reference form: kms_key_arn = aws_kms_key.athena.arn collapses to the resource address.
    const result = run({ encryption_option: 'SSE_KMS', kms_key_arn: 'aws_kms_key.athena' });

    expect(result).toBeNull();
  });
});
