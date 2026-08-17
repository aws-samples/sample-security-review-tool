import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006TfAdapterFactory();

function subnet(name: string, zone: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name,
    address: `aws_subnet.${name}`,
    values: { vpc_id: 'aws_vpc.main', cidr_block: '10.0.0.0/24', availability_zone: zone },
  } as TerraformResource;
}

/** Auto Scaling group wired to three in-project subnets by resource address. */
function buildResources(zones: [string, string, string]): TerraformResource[] {
  const group: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 2,
      max_size: 4,
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b', 'aws_subnet.c'],
    },
  } as TerraformResource;
  return [group, subnet('a', zones[0]), subnet('b', zones[1]), subnet('c', zones[2])];
}

function evaluate(zones: [string, string, string]) {
  const allResources = buildResources(zones);
  const context: TfContext = { projectName: 'test-project', resource: allResources[0], allResources };
  const adapter = factory.bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform: subnet-derived Availability Zone coverage', () => {
  // Primary behavior for this requirement: three subnets covering two distinct zones passes.
  it('passes when three referenced subnets resolve to two distinct Availability Zones', () => {
    expect(evaluate(['us-east-1a', 'us-east-1a', 'us-east-1b'])).toBeNull();
  });

  // Opposite outcome: same three-subnet shape, but every subnet sits in one zone.
  it('flags the group when all three referenced subnets resolve to a single Availability Zone', () => {
    const result = evaluate(['us-east-1a', 'us-east-1a', 'us-east-1a']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
