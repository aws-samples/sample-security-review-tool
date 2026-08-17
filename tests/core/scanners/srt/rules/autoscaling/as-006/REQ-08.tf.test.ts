import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006TfAdapterFactory();

function scan(values: Record<string, unknown>): ScanResult | null {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  };
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 Terraform — empty subnet reference list with no Availability Zones', () => {
  // Primary behaviour owned by this requirement: vpc_zone_identifier present but empty
  // supplies zero subnets, and with no availability_zones the group cannot span two AZs.
  it('flags an Auto Scaling group whose vpc_zone_identifier is an empty list and names no Availability Zones', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      vpc_zone_identifier: [],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: same shape, but the subnet list actually carries two subnets,
  // which satisfies the two-AZ minimum, so nothing is flagged.
  it('does not flag an Auto Scaling group whose vpc_zone_identifier carries two subnets', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b'],
    });

    expect(result).toBeNull();
  });
});
