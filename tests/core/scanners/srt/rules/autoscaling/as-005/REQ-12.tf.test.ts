import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (AS-005): An Auto Scaling group whose `launch_configuration` value comes from a variable
 * with no reachable default (known only at deploy time), with no launch template block and no
 * mixed instances policy, must be flagged: whatever the input resolves to, the group is backed by
 * a launch configuration rather than a launch template.
 */

const factory = new As005TfAdapterFactory();

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function buildContext(values: Record<string, unknown>): TfContext {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;

  return { projectName: 'test-project', resource, allResources: [resource] };
}

function issueFor(key: 'LAUNCH_CONFIGURATION_ONLY'): string {
  const finding = as005Control.findings[key];
  return typeof finding.issue === 'function'
    ? finding.issue({ resourceId: 'aws_autoscaling_group.app', resourceType: 'aws_autoscaling_group' } as never)
    : finding.issue;
}

describe('AS-005 Terraform - deploy-time launch configuration name', () => {
  it('flags a group whose launch_configuration comes from a variable with no default', () => {
    const context = buildContext({
      min_size: 1,
      max_size: 2,
      launch_configuration: unresolved('var.launch_configuration_name'),
    });

    const result = as005Control.run(factory.bind(context), context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.issue).toBe(issueFor('LAUNCH_CONFIGURATION_ONLY'));
  });

  // Opposite outcome: identical group, except a launch template block now backs it, so it passes.
  it('does not flag the same group when it also declares a launch_template block', () => {
    const context = buildContext({
      min_size: 1,
      max_size: 2,
      launch_configuration: unresolved('var.launch_configuration_name'),
      launch_template: [{ id: 'aws_launch_template.lt', version: '$Latest' }],
    });

    const result = as005Control.run(factory.bind(context), context);

    expect(result).toBeNull();
  });
});
