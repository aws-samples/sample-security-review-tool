import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function scan(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 Terraform - query result encryption', () => {
  // REQ-01 (primary): workgroup with no configuration block at all must be flagged.
  it('flags an aws_athena_workgroup defined with no configuration settings at all', () => {
    const resource: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: {
        name: 'analytics-workgroup',
      },
    } as unknown as TerraformResource;

    const result = scan(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  // Opposite outcome: nearest input that flips the verdict — the same workgroup
  // with an explicit query result encryption option present.
  it('does not flag an aws_athena_workgroup that specifies SSE_S3 query result encryption', () => {
    const resource: TerraformResource = {
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
                    encryption_option: 'SSE_S3',
                  },
                ],
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = scan(resource);

    expect(result).toBeNull();
  });
});
