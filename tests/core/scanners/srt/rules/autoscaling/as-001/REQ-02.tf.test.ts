import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values: {
      min_size: 1,
      max_size: 3,
      launch_template: [{ id: 'aws_launch_template.lt' }],
      ...values,
    },
  } as unknown as TerraformResource;
}

function scan(values: Record<string, unknown>): ScanResult | null {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const factory = new As001TfAdapterFactory();
  expect(factory.appliesTo('aws_autoscaling_group')).toBe(true);
  const adapter = factory.bind(context);
  return as001Control.run(adapter as never, context);
}

describe('AS-001 Terraform: Auto Scaling group specifies a default cooldown of 0 seconds', () => {
  // Primary behavior owned by AS-001: an explicit zero cooldown is not a configured nonzero cooldown.
  it('flags an Auto Scaling group with default_cooldown = 0', () => {
    const result = scan({ default_cooldown: 0 });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('aws_autoscaling_group.asg');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });

  it('flags an Auto Scaling group with default_cooldown = "0" written as a string', () => {
    const result = scan({ default_cooldown: '0' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: the nearest input that flips the verdict — cooldown still present, but nonzero.
  it('does not flag an Auto Scaling group with a nonzero default_cooldown of 300', () => {
    expect(scan({ default_cooldown: 300 })).toBeNull();
    expect(scan({ default_cooldown: '300' })).toBeNull();
  });
});
