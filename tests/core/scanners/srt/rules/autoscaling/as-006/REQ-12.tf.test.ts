import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT = 'as-006-project';

function subnet(name: string, zoneId: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name,
    address: `aws_subnet.${name}`,
    values: {
      vpc_id: 'aws_vpc.main',
      cidr_block: '10.0.1.0/24',
      availability_zone_id: zoneId,
    },
  } as TerraformResource;
}

function group(): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 2,
      max_size: 4,
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b'],
    },
  } as TerraformResource;
}

function run(zoneIdA: string, zoneIdB: string): ScanResult | null {
  const asg = group();
  const allResources = [asg, subnet('a', zoneIdA), subnet('b', zoneIdB)];
  const context: TfContext = { projectName: PROJECT, resource: asg, allResources };
  const adapter = new As006TfAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform: subnets whose placement is expressed as AZ IDs', () => {
  // Primary behavior for this requirement: two differing AZ IDs are two distinct AZs.
  it('does not flag a group whose two subnets carry two different availability zone identifiers', () => {
    const result = run('use1-az1', 'use1-az2');

    expect(result).toBeNull();
  });

  // Opposite outcome: identical AZ IDs mean both subnets sit in one Availability Zone.
  it('flags a group whose two subnets carry the same availability zone identifier', () => {
    const result = run('use1-az1', 'use1-az1');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.issue).toContain('same Availability Zone');
  });
});
