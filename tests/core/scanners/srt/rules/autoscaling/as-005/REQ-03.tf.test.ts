import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005TfAdapterFactory();

function evaluate(resource: TerraformResource) {
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  return as005Control.run(factory.bind(context) as As005Adapter, context);
}

describe('AS-005 Terraform - REQ-03: launch template by name plus version, no launch configuration', () => {
  // Primary behaviour owned by this requirement.
  it('returns no finding when the group references a launch template by name and version', () => {
    const resource: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 1,
        max_size: 3,
        launch_template: [{ name: 'app-launch-template', version: '3' }],
      },
    };

    expect(evaluate(resource)).toBeNull();
  });

  // Opposite outcome: identical group except the instance configuration source is a
  // launch configuration instead of a launch template.
  it('returns a finding when the group names a launch configuration instead of a launch template', () => {
    const resource: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 1,
        max_size: 3,
        launch_configuration: 'app-launch-config',
      },
    };

    const result = evaluate(resource);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
