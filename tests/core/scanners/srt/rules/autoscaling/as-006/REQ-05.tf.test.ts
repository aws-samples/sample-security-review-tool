import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_autoscaling_group';
const ADDRESS = 'aws_autoscaling_group.asg';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return { type: RESOURCE_TYPE, name: 'asg', address: ADDRESS, values } as TerraformResource;
}

function run(values: Record<string, unknown>): ScanResult | null {
  const resource = buildResource(values);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new As006TfAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform: empty availability_zones list with no subnets', () => {
  // Primary behaviour owned by this requirement: an empty zone list and no
  // vpc_zone_identifier means zero zones, which cannot span two zones.
  it('flags an Auto Scaling group whose availability_zones list is present but empty and has no vpc_zone_identifier', () => {
    const result = run({
      availability_zones: [],
      min_size: 1,
      max_size: 2,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(ADDRESS);
  });

  // Opposite outcome: the nearest input that flips the verdict — the same group
  // with the zone list populated with two zones must not be flagged.
  it('does not flag the same group when availability_zones holds two zones', () => {
    const result = run({
      availability_zones: ['us-east-1a', 'us-east-1b'],
      min_size: 1,
      max_size: 2,
    });

    expect(result).toBeNull();
  });
});
