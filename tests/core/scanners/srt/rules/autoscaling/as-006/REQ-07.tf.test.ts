import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (AS-006): An Auto Scaling group whose only zone source is a single subnet
 * declared in the same project, with no availability_zones listed, spans exactly one
 * Availability Zone and must be flagged.
 */

const factory = new As006TfAdapterFactory();

function subnet(name: string, zone: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name,
    address: `aws_subnet.${name}`,
    values: { vpc_id: 'aws_vpc.main', cidr_block: '10.0.0.0/24', availability_zone: zone },
  } as TerraformResource;
}

function asg(vpcZoneIdentifier: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 2,
      // Note: no availability_zones argument at all.
      vpc_zone_identifier: vpcZoneIdentifier,
    },
  } as TerraformResource;
}

function run(group: TerraformResource, others: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources: [group, ...others],
  };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 Terraform - REQ-07 single subnet, no availability zones', () => {
  it('flags an Auto Scaling group whose only placement is one subnet declared in the project', () => {
    const group = asg(['aws_subnet.a']);
    const result = run(group, [subnet('a', 'us-east-1a')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  it('flags a single subnet wired as a bare reference string rather than a list', () => {
    const group = asg('aws_subnet.a');
    const result = run(group, [subnet('a', 'us-east-1a')]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });

  // Opposite outcome: nearest input that flips the verdict is a second subnet in
  // another Availability Zone. Multi-subnet coverage belongs to the primary
  // "spans two zones" requirement; asserted here only to discriminate.
  it('does not flag an Auto Scaling group referencing two subnets in different Availability Zones', () => {
    const group = asg(['aws_subnet.a', 'aws_subnet.b']);
    const result = run(group, [subnet('a', 'us-east-1a'), subnet('b', 'us-east-1b')]);

    expect(result).toBeNull();
  });
});
