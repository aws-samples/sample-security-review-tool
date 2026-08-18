import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function buildGroup(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;
}

function scan(group: TerraformResource, allResources: TerraformResource[] = [group]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources,
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform — group attached to a target group with EC2-only health checks', () => {
  it('applies to aws_autoscaling_group', () => {
    expect(factory.appliesTo('aws_autoscaling_group')).toBe(true);
  });

  // Primary behavior owned by this requirement: one target group ARN + health_check_type "EC2" => flag
  it('flags a group that lists one target group and uses EC2 instance status health checks only', () => {
    const group = buildGroup({
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: 'EC2',
    });

    const result = scan(group);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.issue).toContain('EC2 instance status');
  });

  // Opposite outcome: identical group except Elastic Load Balancing health checks are enabled
  it('does not flag the same group when health_check_type is ELB', () => {
    const group = buildGroup({
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: 'ELB',
    });

    expect(scan(group)).toBeNull();
  });
});
