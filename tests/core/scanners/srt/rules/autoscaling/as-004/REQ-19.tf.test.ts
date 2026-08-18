import { describe, expect, it } from 'vitest';
import { as004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.control.js';
import { As004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.tf.js';
import type { As004Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-004/as-004.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As004TfAdapterFactory();

function run(group: TerraformResource, allResources: TerraformResource[] = [group]) {
  const context: TfContext = { projectName: 'test-project', resource: group, allResources };
  const adapter = factory.bind(context) as As004Adapter;
  return as004Control.run(adapter, context);
}

describe('AS-004 Terraform - REQ-19: empty traffic source collection with EC2-only health checks', () => {
  // Primary behavior owned by this requirement: an unattached group may use EC2 health checks.
  it('passes when traffic_source is an empty collection and health_check_type is EC2', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'unattached',
      address: 'aws_autoscaling_group.unattached',
      values: {
        min_size: 1,
        max_size: 2,
        traffic_source: [],
        health_check_type: 'EC2',
      },
    };

    expect(run(group)).toBeNull();
  });

  // Opposite outcome: only the traffic source collection changes - now non-empty.
  it('flags the group when the traffic source collection is non-empty and health_check_type is still EC2', () => {
    const group: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'unattached',
      address: 'aws_autoscaling_group.unattached',
      values: {
        min_size: 1,
        max_size: 2,
        traffic_source: [{ identifier: 'aws_lb_target_group.tg', type: 'elbv2' }],
        health_check_type: 'EC2',
      },
    };

    const result = run(group);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-004');
    expect(result?.resourceName).toBe('aws_autoscaling_group.unattached');
  });
});
