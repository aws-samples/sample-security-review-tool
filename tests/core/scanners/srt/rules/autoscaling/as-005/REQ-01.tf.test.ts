import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_autoscaling_group';
const ADDRESS = 'aws_autoscaling_group.app';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'app',
    address: ADDRESS,
    values,
  } as TerraformResource;
}

function run(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new As005TfAdapterFactory().bind(context);
  return as005Control.run(adapter, context);
}

describe('AS-005 Terraform - Auto Scaling groups must use a launch template rather than a launch configuration', () => {
  // Primary behavior owned by this requirement: launch configuration only -> flag.
  it('flags an Auto Scaling group whose only instance configuration source is a launch configuration', () => {
    const result = run({
      min_size: 1,
      max_size: 3,
      availability_zones: ['us-east-1a'],
      launch_configuration: 'aws_launch_configuration.legacy',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  // Opposite outcome: nearest input that flips the verdict - the same group wired to a
  // launch template block instead of a launch configuration.
  it('does not flag an otherwise identical Auto Scaling group that uses a launch_template block', () => {
    const result = run({
      min_size: 1,
      max_size: 3,
      availability_zones: ['us-east-1a'],
      launch_template: [{ id: 'aws_launch_template.app', version: '$Latest' }],
    });

    expect(result).toBeNull();
  });
});
