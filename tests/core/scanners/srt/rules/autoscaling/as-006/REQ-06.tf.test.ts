import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'web',
    address: 'aws_autoscaling_group.web',
    values,
  } as TerraformResource;
}

function scan(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new As006TfAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 (Terraform) duplicate Availability Zone entries', () => {
  // Primary behavior owned by AS-006: two identical zone entries enable only one distinct AZ.
  it('flags an Auto Scaling group whose availability_zones repeats the same zone and has no vpc_zone_identifier', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      availability_zones: ['us-east-1a', 'us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.web');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: the nearest input that flips the verdict — same two-entry list, distinct zones.
  it('does not flag an Auto Scaling group whose two availability_zones entries are different zones', () => {
    const result = scan({
      min_size: 1,
      max_size: 2,
      availability_zones: ['us-east-1a', 'us-east-1b'],
    });

    expect(result).toBeNull();
  });
});
