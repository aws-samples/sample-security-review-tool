import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005TfAdapterFactory();

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;
}

function scan(values: Record<string, unknown>): ScanResult | null {
  const resource = buildResource(values);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  return as005Control.run(factory.bind(context) as As005Adapter, context);
}

describe('AS-005 (Terraform): Auto Scaling groups must use a launch template', () => {
  // Primary behavior owned by AS-005: an empty launch_configuration leaves the group
  // with no launch-template-based instance configuration, so it must be flagged.
  it('flags a group whose launch_configuration is an empty string with no launch_template and no mixed_instances_policy', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      launch_configuration: '',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same group, still with an
  // empty launch_configuration, but now with a launch_template block naming a template.
  it('does not flag the same group when a launch_template block is present alongside the empty launch_configuration', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      launch_configuration: '',
      launch_template: [{ id: 'aws_launch_template.lt' }],
    });

    expect(result).toBeNull();
  });
});
