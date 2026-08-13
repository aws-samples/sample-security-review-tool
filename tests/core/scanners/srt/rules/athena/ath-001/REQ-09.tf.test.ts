import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (ATH-001): a KMS-based encryption option satisfied by a broad or indirect
 * key identifier (alias, key id, or a reference to a key resource that the plan
 * reader collapses to that resource's address) must PASS.
 */

const factory = new Ath001TfAdapterFactory();

function workgroup(encryptionOption: string, kmsKey: unknown): TerraformResource {
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
              encryption_configuration: [
                { encryption_option: encryptionOption, kms_key_arn: kmsKey },
              ],
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function run(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'analytics-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-09 (Terraform): KMS key supplied as a broad or indirect identifier', () => {
  it('passes when SSE_KMS uses a KMS alias instead of a key ARN', () => {
    expect(run(workgroup('SSE_KMS', 'alias/athena-results'))).toBeNull();
  });

  it('passes when CSE_KMS uses a bare KMS key id instead of a key ARN', () => {
    expect(run(workgroup('CSE_KMS', '1234abcd-12ab-34cd-56ef-1234567890ab'))).toBeNull();
  });

  it('passes when SSE_KMS references a key resource (reference collapses to the resource address)', () => {
    // kms_key_arn = aws_kms_key.results.arn collapses to "aws_kms_key.results".
    expect(run(workgroup('SSE_KMS', 'aws_kms_key.results'))).toBeNull();
  });

  // Opposite outcome: same KMS-based option, key identifier present but empty,
  // so no key is actually specified. Primary behavior owned by the missing-kms-key requirement.
  it('flags when SSE_KMS supplies an empty key identifier', () => {
    const result = run(workgroup('SSE_KMS', '   '));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
