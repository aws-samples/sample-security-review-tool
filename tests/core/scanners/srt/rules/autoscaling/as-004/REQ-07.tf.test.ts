import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const TWO_TARGET_GROUPS = ['aws_lb_target_group.blue', 'aws_lb_target_group.green'];

function buildGroup(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'web',
    address: 'aws_autoscaling_group.web',
    values,
  } as TerraformResource;
}

function scan(group: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };
  const adapter = new As004TfAdapterFactory().bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 (Terraform) - multiple target groups with EC2-only health checks', () => {
  // Primary behavior owned by AS-004: attached to load balancing yet EC2-only health checks.
  it('flags a group listing more than one target group when health_check_type is EC2', () => {
    const result = scan(buildGroup({
      min_size: 2,
      max_size: 6,
      target_group_arns: TWO_TARGET_GROUPS,
      health_check_type: 'EC2',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.web');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: same multi-target-group attachment, but ELB health checks are enabled.
  it('does not flag the same group when health_check_type is ELB', () => {
    const result = scan(buildGroup({
      min_size: 2,
      max_size: 6,
      target_group_arns: TWO_TARGET_GROUPS,
      health_check_type: 'ELB',
    }));

    expect(result).toBeNull();
  });
});
