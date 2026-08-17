import { describe, expect, it } from 'vitest';

import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;
}

function run(values: Record<string, unknown>): ScanResult | null {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = new As006TfAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 (Terraform) - Auto Scaling groups must span at least two Availability Zones', () => {
  // Primary behavior owned by this requirement: exactly one AZ named, no subnets referenced -> flag.
  it('flags an Auto Scaling group that names exactly one availability zone and references no subnets', () => {
    const result = run({
      min_size: 1,
      max_size: 3,
      availability_zones: ['us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: the nearest input that flips the verdict - a second availability zone.
  it('does not flag an Auto Scaling group that names two availability zones and references no subnets', () => {
    const result = run({
      min_size: 1,
      max_size: 3,
      availability_zones: ['us-east-1a', 'us-east-1b'],
    });

    expect(result).toBeNull();
  });

  it('does not flag an Auto Scaling group whose availability zones come from an unresolved variable', () => {
    const result = run({
      min_size: 1,
      max_size: 3,
      availability_zones: unresolved('var.azs'),
    });

    expect(result).toBeNull();
  });
});
