import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006TfAdapterFactory();

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;
}

function scan(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context);
  return as006Control.run(adapter, context);
}

describe('AS-006 Terraform - REQ-01: neither availability_zones nor vpc_zone_identifier specified', () => {
  // Primary behavior owned by this requirement: no placement information at all -> flag.
  it('flags an Auto Scaling group that specifies neither availability_zones nor vpc_zone_identifier', () => {
    const result = scan({
      min_size: 1,
      max_size: 3,
      launch_template: [{ id: 'aws_launch_template.lt' }],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  // Opposite outcome: placement is documented across two AZs, so the requirement is satisfied.
  it('does not flag an Auto Scaling group that specifies two availability_zones', () => {
    const result = scan({
      min_size: 1,
      max_size: 3,
      launch_template: [{ id: 'aws_launch_template.lt' }],
      availability_zones: ['us-east-1a', 'us-east-1b'],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome via the other placement mechanism: two subnets in vpc_zone_identifier.
  it('does not flag an Auto Scaling group that specifies two subnets via vpc_zone_identifier', () => {
    const result = scan({
      min_size: 1,
      max_size: 3,
      launch_template: [{ id: 'aws_launch_template.lt' }],
      vpc_zone_identifier: ['aws_subnet.a', 'aws_subnet.b'],
    });

    expect(result).toBeNull();
  });
});
