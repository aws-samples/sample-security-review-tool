import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-15 (AS-006) — Availability Zones supplied entirely by a deployment-time input
 * (a variable with no reachable default), with no subnets referenced, must NOT be
 * reported: the number of zones is unknown at analysis time.
 */

const factory = new As006TfAdapterFactory();
const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function scan(resource: TerraformResource, allResources: TerraformResource[] = [resource]): ScanResult | null {
  const context: TfContext = { projectName: 'test-project', resource, allResources };
  const adapter = factory.bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform — availability_zones from a deployment-time input', () => {
  it('does not report an Auto Scaling group whose availability_zones is an unresolved variable reference and which references no subnets', () => {
    // Written as: availability_zones = var.azs (no default declared in the project)
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        availability_zones: unresolved('var.azs'),
      },
    };

    expect(scan(asg)).toBeNull();
  });

  it('does not report an Auto Scaling group whose availability_zones entries are all unresolved variable references', () => {
    // Written as: availability_zones = [var.primary_az, var.secondary_az]
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        availability_zones: [unresolved('var.primary_az'), unresolved('var.secondary_az')],
      },
    };

    expect(scan(asg)).toBeNull();
  });

  // Opposite outcome — nearest input that flips the verdict. The zone list is still
  // present, but is a known literal naming exactly one zone, which the
  // single-availability-zone requirement owns (AS-006 primary behavior).
  it('reports an Auto Scaling group whose availability_zones is a known literal naming one zone and which references no subnets', () => {
    const asg: TerraformResource = {
      type: 'aws_autoscaling_group',
      name: 'app',
      address: 'aws_autoscaling_group.app',
      values: {
        min_size: 2,
        max_size: 4,
        availability_zones: ['us-east-1a'],
      },
    };

    const result = scan(asg);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });
});
