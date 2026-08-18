import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005TfAdapterFactory();

function run(values: Record<string, unknown>) {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = factory.bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

const BASE_VALUES = {
  name: 'asg',
  min_size: 1,
  max_size: 3,
  availability_zones: ['us-east-1a'],
};

describe('AS-005 Terraform — mixed instances policy with launch template id and version, no overrides', () => {
  // REQ-04 owns this behavior: a mixed_instances_policy naming a launch template
  // (id + version) with no override blocks means the group runs on a launch template.
  it('does not flag an Auto Scaling group whose mixed instances policy names a launch template by id and version', () => {
    const result = run({
      ...BASE_VALUES,
      mixed_instances_policy: [
        {
          launch_template: [
            {
              launch_template_specification: [
                {
                  launch_template_id: 'aws_launch_template.lt',
                  version: '3',
                },
              ],
            },
          ],
        },
      ],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the same group backed by a launch configuration instead of the
  // mixed instances policy must be flagged.
  it('flags an Auto Scaling group that names a launch configuration instead of a mixed instances policy', () => {
    const result = run({
      ...BASE_VALUES,
      launch_configuration: 'aws_launch_configuration.lc',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
