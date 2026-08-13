import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function workGroup(encryptionConfiguration: Record<string, unknown>): TerraformResource {
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
              output_location: 's3://query-results-bucket/prefix/',
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
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-03 (Terraform): SSE_S3 query result encryption without a KMS key', () => {
  // Primary behavior owned by ATH-001: SSE_S3 is a valid encryption option and needs no kms_key_arn.
  it('passes when encryption_option is SSE_S3 and kms_key_arn is absent', () => {
    const result = run(workGroup({ encryption_option: 'SSE_S3' }));

    expect(result).toBeNull();
  });

  it('passes when encryption_option is SSE_S3 and kms_key_arn is null in planned values', () => {
    const result = run(workGroup({ encryption_option: 'SSE_S3', kms_key_arn: null }));

    expect(result).toBeNull();
  });

  // Opposite outcome: identical fixture except the present encryption option is unsupported.
  it('flags a workgroup whose present encryption_option is not a supported option', () => {
    const result = run(workGroup({ encryption_option: 'AES256' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
