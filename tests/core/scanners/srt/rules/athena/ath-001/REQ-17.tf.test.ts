import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function buildWorkgroup(resultConfiguration: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'disabled',
    address: 'aws_athena_workgroup.disabled',
    values: {
      name: 'disabled-analytics',
      state: 'DISABLED',
      configuration: [
        {
          enforce_workgroup_configuration: true,
          result_configuration: [resultConfiguration],
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

describe('ATH-001 REQ-17 (Terraform): workgroup state does not exempt the encryption requirement', () => {
  // Primary behavior owned by ATH-001: missing query result encryption must be flagged
  // even when the workgroup state is DISABLED, since it can be re-enabled at any time.
  it('flags a DISABLED workgroup that has no encryption_configuration block', () => {
    const result = run(buildWorkgroup({
      output_location: 's3://query-results-bucket/prefix/',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.disabled');
  });

  // Opposite outcome: identical DISABLED workgroup, only the encryption block is present.
  it('does not flag a DISABLED workgroup that has SSE_S3 encryption configured', () => {
    const result = run(buildWorkgroup({
      output_location: 's3://query-results-bucket/prefix/',
      encryption_configuration: [{ encryption_option: 'SSE_S3' }],
    }));

    expect(result).toBeNull();
  });
});
