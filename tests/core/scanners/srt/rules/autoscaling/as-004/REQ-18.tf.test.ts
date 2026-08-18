import { describe, expect, it } from 'vitest';

import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]) {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = new As004TfAdapterFactory().bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 (Terraform): unattached group with Elastic Load Balancing health checks', () => {
  // Primary behavior owned by this requirement: out of scope because nothing is attached.
  it('passes a group with no load_balancers, target_group_arns, traffic_source, or attachment resource and health_check_type ELB', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'a',
      address: 'aws_autoscaling_group.a',
      values: {
        name: 'unattached-group',
        min_size: 1,
        max_size: 2,
        health_check_type: 'ELB',
      },
    };

    expect(scan(group)).toBeNull();
  });

  // Opposite outcome: the nearest input that brings the group into scope with EC2-only health checks.
  it('flags a group with target_group_arns whose health_check_type is EC2', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'a',
      address: 'aws_autoscaling_group.a',
      values: {
        name: 'attached-group',
        min_size: 1,
        max_size: 2,
        target_group_arns: ['aws_lb_target_group.tg'],
        health_check_type: 'EC2',
      },
    };

    const result = scan(group);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.a');
  });
});
