import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As001TfAdapterFactory();

function asg(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'a',
    address: 'aws_autoscaling_group.a',
    values,
  } as TerraformResource;
}

function runControl(resource: TerraformResource) {
  const context = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  } as TfContext;
  const adapter = factory.bind(context);
  return as001Control.run(adapter as never, context);
}

describe('AS-001 Terraform: Auto Scaling Group default cooldown', () => {
  // Primary behaviour owned by this requirement: omitting default_cooldown
  // leaves the service default of 300 seconds, a nonzero cooldown, so it passes.
  it('does not flag an ASG declared with capacity and launch settings but no default_cooldown', () => {
    const result = runControl(
      asg({
        min_size: 1,
        max_size: 3,
        desired_capacity: 2,
        launch_template: [{ id: 'aws_launch_template.lt', version: '$Latest' }],
        availability_zones: ['us-east-1a'],
      }),
    );

    expect(result).toBeNull();
  });

  it('does not flag an ASG whose default_cooldown comes from an unresolved variable reference', () => {
    const result = runControl(
      asg({
        min_size: 1,
        max_size: 3,
        desired_capacity: 2,
        launch_template: [{ id: 'aws_launch_template.lt', version: '$Latest' }],
        default_cooldown: '__unresolved__:var.cooldown',
      }),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is a
  // default_cooldown that is present but zero.
  it('flags an ASG whose default_cooldown is explicitly zero', () => {
    const result = runControl(
      asg({
        min_size: 1,
        max_size: 3,
        desired_capacity: 2,
        launch_template: [{ id: 'aws_launch_template.lt', version: '$Latest' }],
        availability_zones: ['us-east-1a'],
        default_cooldown: 0,
      }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('aws_autoscaling_group.a');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
