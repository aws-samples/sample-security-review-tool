import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 Terraform — attachment list known only at deployment time', () => {
  // REQ-06 owns this behaviour: target_group_arns is unknown, so the rule cannot
  // assert the group is attached to a load balancer; EC2-only checks may be fine.
  it('passes when target_group_arns is an unresolved variable and health_check_type is EC2', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        name: 'app-asg',
        min_size: 1,
        max_size: 2,
        health_check_type: 'EC2',
        target_group_arns: unresolved('var.target_group_arns'),
      },
    };

    expect(scan(group)).toBeNull();
  });

  it('passes when target_group_arns comes from an unresolved local and health_check_type is EC2', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        name: 'app-asg',
        min_size: 1,
        max_size: 2,
        health_check_type: 'EC2',
        target_group_arns: unresolved('local.target_group_arns'),
      },
    };

    expect(scan(group)).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the same group with a
  // known, non-empty target group list. Primary behaviour belongs to the base rule.
  it('flags the same group when target_group_arns resolves to a known non-empty list with EC2 health checks', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        name: 'app-asg',
        min_size: 1,
        max_size: 2,
        health_check_type: 'EC2',
        target_group_arns: ['aws_lb_target_group.tg'],
      },
    };

    const result = scan(group);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
