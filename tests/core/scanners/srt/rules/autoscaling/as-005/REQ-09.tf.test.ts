import { describe, expect, it } from 'vitest';

import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'test-project';

function scan(values: Record<string, unknown>): ScanResult | null {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;
  const context: TfContext = { projectName: PROJECT_NAME, resource, allResources: [resource] };
  const adapter = new As005TfAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

function mixedPolicyValues(specification: Record<string, unknown>): Record<string, unknown> {
  return {
    min_size: 1,
    max_size: 2,
    mixed_instances_policy: [
      {
        launch_template: [
          {
            launch_template_specification: [specification],
          },
        ],
      },
    ],
  };
}

describe('AS-005 (Terraform) mixed instances policy launch template reference', () => {
  // Primary behavior owned by REQ-09: a mixed instances policy launch template
  // specification that supplies only a version identifies no launch template.
  it('flags a group whose mixed instances policy launch template specification supplies only a version', () => {
    const result = scan(mixedPolicyValues({ version: '3' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: the nearest input that flips the verdict — same block,
  // still carrying the version, but now identifying a launch template by id.
  it('does not flag a group whose mixed instances policy launch template specification identifies a launch template alongside the version', () => {
    const result = scan(
      mixedPolicyValues({ launch_template_id: 'aws_launch_template.lt', version: '3' }),
    );

    expect(result).toBeNull();
  });
});
