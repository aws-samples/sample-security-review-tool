import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * AS-006 — Auto Scaling groups must span at least two Availability Zones.
 *
 * REQ-17: an Auto Scaling group referencing two subnets declared in the same project whose
 * `availability_zone` comes from a variable with no reachable default must NOT be flagged:
 * those inputs can legitimately resolve to two distinct zones, so a breach is not certain.
 */

const factory = new As006TfAdapterFactory();
const unresolved = (ref: string): string => `__unresolved__:${ref}`;

function subnet(name: string, zone: string): TerraformResource {
  return {
    type: 'aws_subnet',
    name,
    address: `aws_subnet.${name}`,
    values: { vpc_id: 'aws_vpc.main', cidr_block: '10.0.1.0/24', availability_zone: zone },
  } as TerraformResource;
}

function asg(): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 2,
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b'],
    },
  } as TerraformResource;
}

function run(zoneA: string, zoneB: string): ScanResult | null {
  const group = asg();
  const allResources = [group, subnet('a', zoneA), subnet('b', zoneB)];
  const context: TfContext = { projectName: 'test-project', resource: group, allResources };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 Terraform — subnet Availability Zones supplied at deployment time', () => {
  it('does not flag an Auto Scaling group whose two subnets take their zones from unresolved variables', () => {
    const result = run(unresolved('var.subnet_a_az'), unresolved('var.subnet_b_az'));

    expect(result).toBeNull();
  });

  it('flags the same group when both subnets declare the same literal Availability Zone (owned by the single-zone requirement)', () => {
    // Nearest input that flips the verdict: the zone values are known and identical.
    const result = run('us-east-1a', 'us-east-1a');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  it('does not flag the same group when the two subnets declare two distinct literal Availability Zones', () => {
    const result = run('us-east-1a', 'us-east-1b');

    expect(result).toBeNull();
  });
});
