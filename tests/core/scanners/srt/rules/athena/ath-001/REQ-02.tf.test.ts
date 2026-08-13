import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath001TfAdapterFactory();

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return ath001Control.run(factory.bind(context), context);
}

describe('ATH-001 (Terraform) - query result encryption required', () => {
  // Primary behavior owned by ATH-001: output location without encryption settings must be flagged.
  it('flags a workgroup with configuration and an output location but no query result encryption block', () => {
    const resource: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: {
        name: 'analytics-workgroup',
        configuration: [
          {
            enforce_workgroup_configuration: true,
            publish_cloudwatch_metrics_enabled: true,
            result_configuration: [
              {
                output_location: 's3://athena-results-bucket/queries/',
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const result = run(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceType).toBe('aws_athena_workgroup');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });

  // Opposite outcome: identical fixture except query result encryption is configured.
  it('does not flag the same workgroup when query result encryption is configured with SSE_S3', () => {
    const resource: TerraformResource = {
      type: 'aws_athena_workgroup',
      name: 'analytics',
      address: 'aws_athena_workgroup.analytics',
      values: {
        name: 'analytics-workgroup',
        configuration: [
          {
            enforce_workgroup_configuration: true,
            publish_cloudwatch_metrics_enabled: true,
            result_configuration: [
              {
                output_location: 's3://athena-results-bucket/queries/',
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

    expect(run(resource)).toBeNull();
  });
});
