import { describe, expect, it } from 'vitest';

import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'aws_autoscaling_group';
const ADDRESS = 'aws_autoscaling_group.web';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return { type: RESOURCE_TYPE, name: 'web', address: ADDRESS, values } as TerraformResource;
}

function scan(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new As006TfAdapterFactory().bind(context);
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform - group names two Availability Zones and no subnets', () => {
  // Primary behavior owned by this requirement: two distinct AZs listed, no vpc_zone_identifier -> compliant.
  it('passes when availability_zones lists two distinct zones and no subnets are referenced', () => {
    const result = scan({
      availability_zones: ['us-east-1a', 'us-east-1b'],
      min_size: 2,
      max_size: 4,
    });

    expect(result).toBeNull();
  });

  it('passes when availability_zones lists more than two distinct zones and no subnets are referenced', () => {
    const result = scan({
      availability_zones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
      min_size: 2,
      max_size: 6,
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same shape, but only one zone named -> the multi-AZ span is not met.
  it('flags a group that names only one Availability Zone and no subnets', () => {
    const result = scan({
      availability_zones: ['us-east-1a'],
      min_size: 2,
      max_size: 4,
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(ADDRESS);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });
});
