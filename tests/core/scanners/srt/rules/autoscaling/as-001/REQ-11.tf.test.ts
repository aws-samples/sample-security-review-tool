import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const unresolved = (ref: string): string => `__unresolved__:${ref}`;

function group(defaultCooldown: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 3,
      default_cooldown: defaultCooldown,
    },
  } as unknown as TerraformResource;
}

/** A simple scaling policy attached to the group, declaring its own cooldown. */
function policy(cooldown: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_policy',
    name: 'scale_out',
    address: 'aws_autoscaling_policy.scale_out',
    values: {
      autoscaling_group_name: 'aws_autoscaling_group.app',
      adjustment_type: 'ChangeInCapacity',
      policy_type: 'SimpleScaling',
      scaling_adjustment: 1,
      cooldown,
    },
  } as unknown as TerraformResource;
}

function bind(asg: TerraformResource, pol: TerraformResource): { adapter: As001Adapter; context: TfContext } {
  const context: TfContext = {
    projectName: 'test-project',
    resource: asg,
    allResources: [asg, pol],
  };
  return { adapter: new As001TfAdapterFactory().bind(context), context };
}

describe('AS-001 Terraform — group default_cooldown of 0 alongside a policy-level cooldown', () => {
  // Primary behavior owned by AS-001: the group's own default cooldown must be nonzero.
  it('flags the group when default_cooldown is 0 even though the attached simple scaling policy sets a nonzero cooldown', () => {
    const { adapter, context } = bind(group(0), policy(300));

    const result = as001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe('aws_autoscaling_group.app');
    expect(result!.resourceType).toBe('aws_autoscaling_group');
  });

  it('flags the group when default_cooldown is the string "0" with a nonzero policy cooldown', () => {
    const { adapter, context } = bind(group('0'), policy(300));

    expect(as001Control.run(adapter, context)).not.toBeNull();
  });

  // Opposite outcome: only the group's own default cooldown changes to a nonzero value.
  it('does not flag the group when its own default_cooldown is nonzero while the policy cooldown is 0', () => {
    const { adapter, context } = bind(group(300), policy(0));

    expect(as001Control.run(adapter, context)).toBeNull();
  });

  it('does not flag the group when default_cooldown comes from an unresolved variable reference', () => {
    const { adapter, context } = bind(group(unresolved('var.cooldown')), policy(300));

    expect(as001Control.run(adapter, context)).toBeNull();
  });
});
