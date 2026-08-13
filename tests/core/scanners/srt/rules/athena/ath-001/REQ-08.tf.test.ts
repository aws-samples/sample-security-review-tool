import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function buildWorkgroup(encryptionOption: string, kmsKey: unknown): TerraformResource {
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
              encryption_configuration: [
                {
                  encryption_option: encryptionOption,
                  ...(kmsKey === undefined ? {} : { kms_key_arn: kmsKey }),
                },
              ],
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function scan(encryptionOption: string, kmsKey: unknown) {
  const resource = buildWorkgroup(encryptionOption, kmsKey);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 Terraform — KMS-based encryption with a blank key identifier', () => {
  // Primary behavior owned by this requirement: a blank kms_key_arn does not
  // identify a key, so it must be flagged.
  it('flags SSE_KMS with an empty string kms_key_arn', () => {
    const result = scan('SSE_KMS', '');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
  });

  it('flags SSE_KMS with a whitespace-only kms_key_arn', () => {
    const result = scan('SSE_KMS', '   ');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  it('flags CSE_KMS with a whitespace-only kms_key_arn (tabs and newlines)', () => {
    const result = scan('CSE_KMS', '\t\n ');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  // Opposite outcome: nearest input that flips the verdict — same KMS-based
  // option, but the key is wired as a reference to a real KMS key resource
  // (collapsed by the plan reader to the resource address).
  it('does not flag SSE_KMS when kms_key_arn references a real KMS key resource', () => {
    const result = scan('SSE_KMS', 'aws_kms_key.athena');
    expect(result).toBeNull();
  });
});
