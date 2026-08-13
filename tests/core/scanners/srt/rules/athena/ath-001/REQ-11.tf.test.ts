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
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              output_location: 's3://query-results/',
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

describe('ATH-001 Terraform - empty query result encryption settings', () => {
  // Primary behavior owned by this requirement: an encryption_configuration
  // block with no encryption option inside provides no encryption.
  it('flags a workgroup whose encryption_configuration block is empty', () => {
    const result = run(workGroup({}));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  // Opposite outcome: nearest input that flips the verdict - the same
  // encryption_configuration block, populated with a supported option.
  it('does not flag a workgroup whose encryption_configuration specifies SSE_S3', () => {
    const result = run(workGroup({ encryption_option: 'SSE_S3' }));

    expect(result).toBeNull();
  });
});
