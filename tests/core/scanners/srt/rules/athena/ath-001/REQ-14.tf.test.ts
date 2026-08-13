import { describe, it, expect } from 'vitest';
import { ath001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.control.js';
import { Ath001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.tf.js';
import type { Ath001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-001/ath-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-14 (Terraform)
 * ATH-001: Athena workgroups must have query result encryption enabled using SSE_S3,
 * SSE_KMS, or CSE_KMS, with a KMS key specified when SSE_KMS or CSE_KMS is used.
 *
 * Scenario owned by this file: whether query result encryption settings exist at all is
 * governed by a condition the plan cannot resolve. The plan reader records such values as
 * `null`, which means "unknown" — the analyzer cannot prove the deployed workgroup lacks
 * encryption, so no finding may be raised.
 */

const factory = new Ath001TfAdapterFactory();

function runControl(values: Record<string, unknown>) {
  const resource: TerraformResource = {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values,
  } as TerraformResource;

  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as Ath001Adapter;
  return ath001Control.run(adapter, context);
}

describe('ATH-001 REQ-14 (Terraform): indeterminate query result encryption settings', () => {
  it('returns no finding when the configuration block is unknown at plan time', () => {
    const result = runControl({ name: 'analytics', configuration: null });

    expect(result).toBeNull();
  });

  it('returns no finding when the result_configuration block is unknown at plan time', () => {
    const result = runControl({
      name: 'analytics',
      configuration: [{ result_configuration: null }],
    });

    expect(result).toBeNull();
  });

  it('returns no finding when the encryption_configuration block is unknown at plan time', () => {
    const result = runControl({
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              output_location: 's3://results/',
              encryption_configuration: null,
            },
          ],
        },
      ],
    });

    expect(result).toBeNull();
  });

  it('returns no finding when the encryption_option value is unknown at plan time', () => {
    const result = runControl({
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              encryption_configuration: [{ encryption_option: null }],
            },
          ],
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: primary behavior for the unsupported-option case is owned by the
  // "missing query result encryption" requirement. Only the resolvability of the
  // encryption option changes relative to the tests above.
  it('flags the workgroup when the encryption option is known but not a supported option', () => {
    const result = runControl({
      name: 'analytics',
      configuration: [
        {
          result_configuration: [
            {
              encryption_configuration: [{ encryption_option: 'AES256' }],
            },
          ],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-001');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
