import { describe, it, expect } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function runControl(healthCheckType: string) {
  const group: TerraformResource = {
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

  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };

  return as004Control.run(factory.bind(context), context);
}

describe('AS-004 Terraform: health check type naming multiple non-ELB services', () => {
  // Primary behavior owned by AS-004: attached to a target group, health check
  // type lists several services but none of them is Elastic Load Balancing.
  it('flags a group with target_group_arns whose health_check_type is "EC2,EBS"', () => {
    const result = runControl('EC2,EBS');

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-004');
    expect(result!.resourceName).toBe('aws_autoscaling_group.app');
    expect(result!.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: same attachment, same multi-service list, but ELB is one
  // of the named services, so load balancer health results are honoured.
  it('does not flag a group whose multi-service health_check_type includes ELB', () => {
    expect(runControl('EC2,ELB,EBS')).toBeNull();
  });
});
