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
  } as unknown as TerraformResource;
}

function evaluate(resource: TerraformResource, allResources: TerraformResource[] = [resource]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform — group attached to a target group', () => {
  // Primary behavior owned by REQ-09: ELB health checks on an attached group pass.
  it('passes when the group lists a target group and health_check_type is ELB', () => {
    const result = evaluate(buildGroup({
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: 'ELB',
    }));

    expect(result).toBeNull();
  });

  // Opposite outcome: only the health check type changes to instance-status-only.
  it('flags the same group when health_check_type is EC2 instead of ELB', () => {
    const result = evaluate(buildGroup({
      min_size: 1,
      max_size: 3,
      target_group_arns: ['aws_lb_target_group.app'],
      health_check_type: 'EC2',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
