import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * AS-006: Auto Scaling groups must span at least two Availability Zones.
 *
 * Requirement under test (primary behavior owned by AS-006): when one of the group's
 * availability_zones entries comes from a deployment-time input (a `var.` reference with
 * no reachable default, which the source reader marks unresolved), the identity of that
 * zone is not knowable at analysis time, so no breach can be asserted.
 */

const ADDRESS = 'aws_autoscaling_group.app';

function unresolved(reference: string): string {
  return `__unresolved__:${reference}`;
}

function buildGroup(availabilityZones: unknown[]): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: ADDRESS,
    values: {
      min_size: 2,
      max_size: 4,
      availability_zones: availabilityZones,
    },
  } as unknown as TerraformResource;
}

function runControl(group: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };
  const adapter = new As006TfAdapterFactory().bind(context);
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform: zone list mixes a literal Availability Zone with a deployment-time input', () => {
  it('does not report a finding when the second zone entry is an unresolved input variable and no subnets are referenced', () => {
    const result = runControl(buildGroup(['us-east-1a', unresolved('var.secondary_az')]));

    expect(result).toBeNull();
  });

  // Opposite outcome: same shape, but the second entry is a known duplicate of the first,
  // so the group is provably confined to a single Availability Zone.
  it('reports a finding when the second zone entry is a known duplicate of the first zone', () => {
    const result = runControl(buildGroup(['us-east-1a', 'us-east-1a']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(ADDRESS);
  });
});
