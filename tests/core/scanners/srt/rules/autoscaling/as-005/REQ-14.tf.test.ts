import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005TfAdapterFactory();

function contextFor(values: Record<string, unknown>): TfContext {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;

  return { projectName: 'test-project', resource, allResources: [resource] };
}

function run(values: Record<string, unknown>) {
  const context = contextFor(values);
  return as005Control.run(factory.bind(context), context);
}

describe('AS-005 (Terraform): launch_template block with an empty id', () => {
  // Primary behavior owned by AS-005: an empty launch template id is not a usable launch template.
  it('flags an Auto Scaling group whose launch_template block sets id to an empty string and names no launch configuration', () => {
    const result = run({
      min_size: 1,
      max_size: 2,
      launch_template: [{ id: '', version: '$Latest' }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
  });

  it('does not flag the same group when the launch_template id is a usable, non-empty reference (opposite outcome)', () => {
    const result = run({
      min_size: 1,
      max_size: 2,
      launch_template: [{ id: 'aws_launch_template.lt', version: '$Latest' }],
    });

    expect(result).toBeNull();
  });
});
