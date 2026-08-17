import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006TfAdapterFactory();

function subnetInZone(zone: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name: 'b',
    address: 'aws_subnet.b',
    values: {
      vpc_id: 'aws_vpc.main',
      cidr_block: '10.0.1.0/24',
      availability_zone: zone,
    },
  } as TerraformResource;
}

function group(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: { min_size: 1, max_size: 2, ...values },
  } as TerraformResource;
}

function scan(asg: TerraformResource, subnet: TerraformResource): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: asg,
    allResources: [asg, subnet],
  };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 Terraform - one named Availability Zone plus a single subnet in a different zone', () => {
  // Primary behavior owned by AS-006: one named AZ plus one subnet is single-zone
  // capacity on either dimension, and a subnet outside the named zone is invalid
  // rather than a second usable zone.
  it('flags an Auto Scaling group naming one Availability Zone and one subnet assigned to a different Availability Zone', () => {
    const asg = group({
      availability_zones: ['us-east-1a'],
      vpc_zone_identifier: ['aws_subnet.b'],
    });

    const result = scan(asg, subnetInZone('us-east-1b'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: the nearest configuration that genuinely spans two zones -
  // two named Availability Zones with the subnet residing in one of them.
  it('does not flag an Auto Scaling group naming two Availability Zones with its subnet inside one of them', () => {
    const asg = group({
      availability_zones: ['us-east-1a', 'us-east-1b'],
      vpc_zone_identifier: ['aws_subnet.b'],
    });

    expect(scan(asg, subnetInZone('us-east-1b'))).toBeNull();
  });
});
