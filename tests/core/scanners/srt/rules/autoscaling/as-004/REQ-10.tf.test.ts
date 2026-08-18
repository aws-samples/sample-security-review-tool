import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function group(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'web',
    address: 'aws_autoscaling_group.web',
    values,
  } as TerraformResource;
}

function run(resource: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform — target group attached with health_check_type omitted (REQ-10)', () => {
  // Primary behavior owned by this requirement: target_group_arns present and health_check_type
  // absent means EC2 status checks only, so the group must be flagged.
  it('flags a group that lists a target group and specifies no health_check_type', () => {
    const result = run(group({
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.web');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: only the health check type changes — it is present and set to ELB.
  it('does not flag the same group when health_check_type is set to ELB', () => {
    const result = run(group({
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: 'ELB',
    }));

    expect(result).toBeNull();
  });
});
