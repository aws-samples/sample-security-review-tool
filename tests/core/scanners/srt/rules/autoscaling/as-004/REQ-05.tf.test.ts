import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function scan(values: Record<string, unknown>): ScanResult | null {
  const group: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;

  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group],
  };

  const factory = new As004TfAdapterFactory();
  expect(factory.appliesTo('aws_autoscaling_group')).toBe(true);
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform — REQ-05: no load balancer or target group attached', () => {
  // Primary behavior owned by this requirement: with both load_balancers and
  // target_group_arns empty nothing is attached, so health_check_type "EC2" passes.
  it('passes an Auto Scaling group with empty load_balancers and empty target_group_arns using EC2 health checks', () => {
    const result = scan({
      min_size: 1,
      max_size: 3,
      load_balancers: [],
      target_group_arns: [],
      health_check_type: 'EC2',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: only the target group collection changes to non-empty, so
  // the group is attached and EC2-only health checks must be flagged.
  it('flags the otherwise identical group when target_group_arns contains an entry', () => {
    const result = scan({
      min_size: 1,
      max_size: 3,
      load_balancers: [],
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: 'EC2',
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-004');
    expect(result!.resourceName).toBe('aws_autoscaling_group.app');
    expect(result!.resourceType).toBe('aws_autoscaling_group');
  });
});
