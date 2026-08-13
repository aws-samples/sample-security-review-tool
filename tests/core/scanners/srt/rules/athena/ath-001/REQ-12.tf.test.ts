import { describe, expect, it } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function workGroup(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: { name: 'analytics', ...values },
  } as unknown as TerraformResource;
}

function scan(resource: TerraformResource): ReturnType<typeof ath001Control.run> {
  const context: TfContext = {
    projectName: 'analytics-project',
    resource,
    allResources: [resource],
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 (Terraform) - result settings that explicitly remove or clear query result encryption', () => {
  // REQ-12 owns this behavior: clearing the encryption configuration must be flagged.
  it('flags a workgroup whose result_configuration sets encryption_configuration to an empty list', () => {
    const result = scan(
      workGroup({
        configuration: [
          {
            result_configuration: [
              {
                output_location: 's3://analytics-results/',
                encryption_configuration: [],
              },
            ],
          },
        ],
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  // REQ-12: an emptied encryption_configuration block leaves no enforced encryption.
  it('flags a workgroup whose encryption_configuration block has been cleared of its encryption option', () => {
    const result = scan(
      workGroup({
        configuration: [
          {
            result_configuration: [
              {
                output_location: 's3://analytics-results/',
                encryption_configuration: [{ encryption_option: null, kms_key_arn: null }],
              },
            ],
          },
        ],
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
  });

  // Opposite outcome: identical fixture except the encryption configuration is retained.
  it('does not flag a workgroup whose result_configuration retains SSE_S3 query result encryption', () => {
    const result = scan(
      workGroup({
        configuration: [
          {
            result_configuration: [
              {
                output_location: 's3://analytics-results/',
                encryption_configuration: [{ encryption_option: 'SSE_S3' }],
              },
            ],
          },
        ],
      }),
    );

    expect(result).toBeNull();
  });
});
