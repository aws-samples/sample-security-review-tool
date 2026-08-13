import { describe, expect, it } from 'vitest';
import { ath002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.control.js';
import { Ath002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.tf.js';
import type { Ath002Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/athena/ath-002/ath-002.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Ath002TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context) as Ath002Adapter;
  return ath002Control.run(adapter, context);
}

/**
 * Builds a workgroup that relies on Athena managed query result storage.
 * `managedEnabled` is the only thing that varies between the primary and opposite cases.
 */
function workGroupWithManagedStorage(managedEnabled: boolean): TerraformResource {
  return {
    type: 'aws_athena_workgroup',
    name: 'analytics',
    address: 'aws_athena_workgroup.analytics',
    values: {
      name: 'analytics-workgroup',
      configuration: [
        {
          enforce_workgroup_configuration: true,
          managed_query_results_configuration: [
            {
              enabled: managedEnabled,
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

describe('ATH-002 REQ-16 (Terraform): managed query results storage', () => {
  // Primary behavior owned by this requirement: managed storage means there is no
  // customer output bucket, so no bucket-policy finding applies.
  it('passes a workgroup that uses Athena managed query results storage instead of a customer bucket', () => {
    const workgroup = workGroupWithManagedStorage(true);

    const result = scan(workgroup, [workgroup]);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical workgroup except managed storage is switched off,
  // leaving no query-result location at all (ATH-002 missing-output-location).
  it('flags an otherwise identical workgroup whose managed query results storage is disabled', () => {
    const workgroup = workGroupWithManagedStorage(false);

    const result = scan(workgroup, [workgroup]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('ATH-002');
    expect(result?.resourceName).toBe('aws_athena_workgroup.analytics');
  });
});
