import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ADDRESS = 'aws_autoscaling_group.asg';

function evaluateGroup(values: Record<string, unknown>): ScanResult | null {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: ADDRESS,
    values,
  } as TerraformResource;
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new As005TfAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

describe('AS-005 (Terraform): mixed instances policy without any launch template specification', () => {
  // Primary behaviour owned by AS-005: a mixed_instances_policy that supplies no
  // launch_template_specification supplies no launch template, so the group must be flagged.
  it('flags a group whose mixed_instances_policy contains no launch template specification', () => {
    const result = evaluateGroup({
      min_size: 1,
      max_size: 3,
      mixed_instances_policy: [
        {
          instances_distribution: [
            {
              on_demand_base_capacity: 1,
              spot_allocation_strategy: 'capacity-optimized',
            },
          ],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  it('flags a group whose mixed_instances_policy launch_template block has no specification', () => {
    const result = evaluateGroup({
      min_size: 1,
      max_size: 3,
      mixed_instances_policy: [
        {
          launch_template: [
            {
              override: [{ instance_type: 'm5.large' }],
            },
          ],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
  });

  // Opposite outcome: identical group except the mixed instances policy does name a launch
  // template, which is exactly what the requirement turns on.
  it('does not flag a group whose mixed_instances_policy names a launch template', () => {
    const result = evaluateGroup({
      min_size: 1,
      max_size: 3,
      mixed_instances_policy: [
        {
          instances_distribution: [
            {
              on_demand_base_capacity: 1,
              spot_allocation_strategy: 'capacity-optimized',
            },
          ],
          launch_template: [
            {
              launch_template_specification: [
                {
                  launch_template_id: 'aws_launch_template.lt',
                  version: '$Latest',
                },
              ],
            },
          ],
        },
      ],
    });

    expect(result).toBeNull();
  });
});
