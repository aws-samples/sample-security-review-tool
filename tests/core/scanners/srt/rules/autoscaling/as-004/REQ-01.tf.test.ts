import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function asg(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;
}

function run(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = new As004TfAdapterFactory().bind(context);
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform — REQ-01: classic load balancer attachment with EC2-only health checks', () => {
  // Primary behavior owned by this requirement: attached to a classic load
  // balancer while health check type is EC2 instance status only -> flag.
  it('flags a group that lists a classic load balancer name and sets health_check_type EC2', () => {
    const resource = asg({
      min_size: 1,
      max_size: 3,
      load_balancers: ['my-classic-lb'],
      health_check_type: 'EC2',
    });

    const result = run(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: only health_check_type flips to ELB, the classic load
  // balancer attachment is unchanged.
  it('does not flag the same classic-load-balancer group when health_check_type is ELB', () => {
    const resource = asg({
      min_size: 1,
      max_size: 3,
      load_balancers: ['my-classic-lb'],
      health_check_type: 'ELB',
    });

    expect(run(resource)).toBeNull();
  });
});
