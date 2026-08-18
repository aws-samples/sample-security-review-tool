import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { TfContext, TerraformResource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005TfAdapterFactory();

function scan(values: Record<string, unknown>): ScanResult | null {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;

  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };

  return as005Control.run(factory.bind(context) as As005Adapter, context);
}

describe('AS-005 Terraform — REQ-08: launch_template block that identifies no launch template', () => {
  // Primary behavior owned by this requirement: a launch_template block with only
  // version identifies no launch template, so the group must be flagged.
  it('flags a group whose launch_template block supplies only version', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      launch_template: [{ version: '$Latest' }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  it('flags a group whose launch_template block supplies only a numeric version', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      launch_template: [{ version: 3 }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same block
  // now identifies a launch template by id, so the reference resolves.
  it('does not flag a group whose launch_template block sets id alongside version', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      launch_template: [{ id: 'aws_launch_template.lt', version: '$Latest' }],
    });

    expect(result).toBeNull();
  });

  it('does not flag a group whose launch_template block sets name alongside version', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      launch_template: [{ name: 'my-template', version: '$Latest' }],
    });

    expect(result).toBeNull();
  });
});
