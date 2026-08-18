import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function runControl(resource: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new As005TfAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

describe('AS-005 Terraform — REQ-02: launch template referenced by id plus version, no launch configuration', () => {
  // Primary behaviour owned by this requirement: a launch_template block giving
  // id and version, with no launch_configuration argument, is compliant.
  it('does not flag an Auto Scaling group whose launch_template block gives id and version', () => {
    const result = runControl({
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 1,
        max_size: 3,
        launch_template: [
          {
            id: 'aws_launch_template.lt',
            version: '3',
          },
        ],
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same group, but its instance configuration comes from a
  // launch configuration instead of a launch template.
  it('flags an Auto Scaling group that names a launch_configuration instead of a launch_template', () => {
    const result = runControl({
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 1,
        max_size: 3,
        launch_configuration: 'aws_launch_configuration.lc',
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
