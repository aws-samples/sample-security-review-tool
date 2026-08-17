import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT = 'as-001-req-09-project';

/** A simple scaling policy attached to the group that declares its own nonzero cooldown. */
const policy: TerraformResource = {
  type: 'aws_autoscaling_policy',
  name: 'scale_out',
  address: 'aws_autoscaling_policy.scale_out',
  values: {
    name: 'scale-out',
    autoscaling_group_name: 'aws_autoscaling_group.app',
    policy_type: 'SimpleScaling',
    adjustment_type: 'ChangeInCapacity',
    scaling_adjustment: 1,
    cooldown: 120,
  },
};

function buildGroup(extraValues: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      name: 'app',
      min_size: 1,
      max_size: 3,
      launch_template: [{ id: 'aws_launch_template.lt' }],
      ...extraValues,
    },
  };
}

function evaluate(group: TerraformResource) {
  const context: TfContext = { projectName: PROJECT, resource: group, allResources: [group, policy] };
  const adapter = new As001TfAdapterFactory().bind(context) as As001Adapter;
  return { adapter, result: as001Control.run(adapter, context) };
}

describe('AS-001 Terraform - REQ-09: group omits default_cooldown while a simple scaling policy sets its own cooldown', () => {
  it('does not flag the group when default_cooldown is absent and the attached simple scaling policy declares a nonzero cooldown', () => {
    // Primary behaviour owned by this requirement: an absent default_cooldown still
    // runs with the nonzero service default of 300 seconds, so the rule passes.
    const { adapter, result } = evaluate(buildGroup({}));

    expect(adapter.cooldownState).toBe('absent');
    expect(result).toBeNull();
  });

  it('opposite case: flags the group when it explicitly sets default_cooldown to zero despite the policy cooldown', () => {
    // Nearest input that flips the verdict: the group's own cooldown is present but zero.
    const { adapter, result } = evaluate(buildGroup({ default_cooldown: 0 }));

    expect(adapter.cooldownState).toBe('zero');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
