import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006TfAdapterFactory();

function subnet(name: string, zone: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name,
    address: `aws_subnet.${name}`,
    values: { vpc_id: 'aws_vpc.main', cidr_block: '10.0.1.0/24', availability_zone: zone },
  } as TerraformResource;
}

/** Group names no availability_zones and places instances via two subnet references. */
function group(): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values: {
      min_size: 2,
      max_size: 4,
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b'],
    },
  } as TerraformResource;
}

function run(zoneA: string, zoneB: string): ScanResult | null {
  const asg = group();
  const allResources = [asg, subnet('a', zoneA), subnet('b', zoneB)];
  const context: TfContext = { projectName: 'test-project', resource: asg, allResources };
  return as006Control.run(factory.bind(context) as As006Adapter, context);
}

describe('AS-006 Terraform: subnets resolving to a single Availability Zone', () => {
  // Primary behavior owned by AS-006: two subnets, same availability_zone, no availability_zones listed.
  it('flags an Auto Scaling group whose two referenced subnets are both in the same Availability Zone', () => {
    const result = run('us-east-1a', 'us-east-1a');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Nearest input that flips the verdict: identical config, one subnet moved to another zone.
  it('does not flag when the two referenced subnets are in different Availability Zones', () => {
    const result = run('us-east-1a', 'us-east-1b');

    expect(result).toBeNull();
  });
});
