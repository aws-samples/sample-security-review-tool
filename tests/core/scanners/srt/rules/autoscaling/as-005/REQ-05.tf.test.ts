import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005TfAdapterFactory();

function scan(resource: TerraformResource): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = factory.bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

/**
 * REQ-05 (AS-005): a mixed_instances_policy sources instances only from launch
 * templates — the base launch_template_specification plus per-instance-type
 * overrides each naming their own launch template — so the group passes.
 */
describe('AS-005 Terraform — mixed instances policy with per-instance-type launch template overrides', () => {
  it('does not flag a group whose mixed_instances_policy has a base launch template and override launch templates', () => {
    const resource: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'mixed',
      address: 'aws_autoscaling_group.mixed',
      values: {
        min_size: 1,
        max_size: 4,
        mixed_instances_policy: [
          {
            launch_template: [
              {
                launch_template_specification: [
                  { launch_template_id: 'aws_launch_template.base', version: '$Latest' },
                ],
                override: [
                  {
                    instance_type: 'm5.large',
                    launch_template_specification: [
                      { launch_template_id: 'aws_launch_template.m5', version: '$Latest' },
                    ],
                  },
                  {
                    instance_type: 'c5.large',
                    launch_template_specification: [
                      { launch_template_id: 'aws_launch_template.c5', version: '$Latest' },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      },
    };

    expect(scan(resource)).toBeNull();
  });

  // Opposite outcome: identical group except the instance configuration comes
  // from a launch configuration instead of the mixed instances policy.
  it('flags a group that names a launch configuration instead of a mixed instances policy', () => {
    const resource: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'legacy',
      address: 'aws_autoscaling_group.legacy',
      values: {
        min_size: 1,
        max_size: 4,
        launch_configuration: 'aws_launch_configuration.legacy',
      },
    };

    const result = scan(resource);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.legacy');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
