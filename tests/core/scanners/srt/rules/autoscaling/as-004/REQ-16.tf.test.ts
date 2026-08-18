import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function buildGroup(healthCheckType: string): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: healthCheckType,
    },
  } as unknown as TerraformResource;
}

function scan(group: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform — target group attached group with empty health check type', () => {
  // Primary behavior owned by AS-004: an empty health_check_type contains no
  // "ELB" entry, so the group falls back to EC2 status checks only.
  it('flags a group that lists target_group_arns and sets health_check_type to an empty string', () => {
    const result = scan(buildGroup(''));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  it('does not flag the same group when health_check_type names ELB instead of being empty', () => {
    const result = scan(buildGroup('ELB'));

    expect(result).toBeNull();
  });
});
