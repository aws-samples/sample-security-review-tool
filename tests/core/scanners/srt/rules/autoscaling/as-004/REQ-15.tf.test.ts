import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function buildGroup(healthCheckType: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'web',
    address: 'aws_autoscaling_group.web',
    values: {
      min_size: 1,
      max_size: 2,
      target_group_arns: ['aws_lb_target_group.tg'],
      health_check_type: healthCheckType,
    },
  } as TerraformResource;
}

function run(group: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 (Terraform) — health check type supplied by a deployment-time value', () => {
  // REQ-15 owns this behavior: an unresolvable health check type cannot be asserted a breach.
  it('passes when the group lists a target group and health_check_type comes from an unresolved variable', () => {
    expect(run(buildGroup(unresolved('var.health_check_type')))).toBeNull();
  });

  it('passes when health_check_type is a partially interpolated string', () => {
    expect(run(buildGroup('${var.health_check_type}'))).toBeNull();
  });

  // Opposite outcome: same fixture, but the health check type is a resolved instance-status-only value.
  it('flags the group when the same fixture resolves health_check_type to EC2', () => {
    const result = run(buildGroup('EC2'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.web');
  });
});
