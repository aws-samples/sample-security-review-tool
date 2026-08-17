import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (AS-006): An Auto Scaling group with no availability_zones whose
 * vpc_zone_identifier references two subnets declared in the same project, each in a
 * DIFFERENT availability_zone, spans two zones and must pass.
 *
 * References collapse to the target resource address, e.g. "aws_subnet.a".
 */

const factory = new As006TfAdapterFactory();

function subnet(name: string, zone: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name,
    address: `aws_subnet.${name}`,
    values: {
      vpc_id: 'aws_vpc.main',
      cidr_block: '10.0.1.0/24',
      availability_zone: zone,
    },
  } as unknown as TerraformResource;
}

function asg(): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 2,
      max_size: 4,
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b'],
    },
  } as unknown as TerraformResource;
}

function run(zoneA: string, zoneB: string) {
  const group = asg();
  const allResources = [group, subnet('a', zoneA), subnet('b', zoneB)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources,
  };
  return as006Control.run(factory.bind(context) as any, context);
}

describe('AS-006 Terraform — subnets across availability zones', () => {
  it('passes when the two referenced subnets are in different availability zones and none are named', () => {
    const result = run('us-east-1a', 'us-east-1b');

    expect(result).toBeNull();
  });

  // Opposite outcome: identical wiring, but both subnets sit in one availability zone,
  // so the group does not span two zones. (Primary behavior owned by REQ-09.)
  it('flags when the two referenced subnets are in the same availability zone', () => {
    const result = run('us-east-1a', 'us-east-1a');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });
});
