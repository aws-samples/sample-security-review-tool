import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-20 (AS-006): An Auto Scaling group whose placement list holds exactly ONE entry is
 * confined to a single Availability Zone, even when that entry's zone comes from a
 * deployment-time input (an unresolved `var.` reference). One subnet — or one zone entry —
 * must be flagged.
 */

const factory = new As006TfAdapterFactory();
const unresolved = (ref: string): string => `__unresolved__:${ref}`;

function runControl(resource: TerraformResource, allResources: TerraformResource[]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  return as006Control.run(factory.bind(context), context);
}

/** Subnet whose availability zone is supplied by a deployment-time input. */
const deployTimeSubnet = (name: string): TerraformResource => ({
  type: 'aws_subnet',
  name,
  address: `aws_subnet.${name}`,
  values: { vpc_id: 'aws_vpc.main', cidr_block: '10.0.1.0/24', availability_zone: unresolved('var.az') },
});

describe('AS-006 REQ-20 (Terraform): single-entry placement list is one Availability Zone', () => {
  it('flags a group whose vpc_zone_identifier holds one subnet reference with a deployment-time zone', () => {
    const subnet = deployTimeSubnet('a');
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: { min_size: 1, max_size: 2, vpc_zone_identifier: [subnet.address] },
    };

    const result = runControl(asg, [asg, subnet]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  it('flags a group whose vpc_zone_identifier holds a single literal subnet id', () => {
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: { min_size: 1, max_size: 2, vpc_zone_identifier: ['subnet-0abc123'] },
    };

    const result = runControl(asg, [asg]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });

  it('flags a group whose availability_zones list holds exactly one deployment-time entry', () => {
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: { min_size: 1, max_size: 2, availability_zones: [unresolved('var.az')] },
    };

    const result = runControl(asg, [asg]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });

  // Opposite outcome: only the entry count changes — two subnets can reach two zones, so
  // unknown zones per subnet are not a breach.
  it('does not flag a group whose vpc_zone_identifier holds two subnet references with deployment-time zones', () => {
    const subnetA = deployTimeSubnet('a');
    const subnetB = deployTimeSubnet('b');
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: { min_size: 1, max_size: 2, vpc_zone_identifier: [subnetA.address, subnetB.address] },
    };

    expect(runControl(asg, [asg, subnetA, subnetB])).toBeNull();
  });

  // Opposite outcome on the zone side: two named zones satisfy the requirement.
  it('does not flag a group whose availability_zones list holds two distinct zones', () => {
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: { min_size: 1, max_size: 2, availability_zones: ['us-east-1a', 'us-east-1b'] },
    };

    expect(runControl(asg, [asg])).toBeNull();
  });
});
