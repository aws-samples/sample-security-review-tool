import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-05 (AS-001): an Auto Scaling group whose default_cooldown is negative
// (e.g. -1 seconds) describes no waiting period at all, so it must be flagged.

const factory = new As001TfAdapterFactory();

function buildContext(cooldown: unknown): TfContext {
  const values: Record<string, unknown> = {
    min_size: 1,
    max_size: 3,
    availability_zones: ['us-east-1a'],
  };
  if (cooldown !== undefined) values['default_cooldown'] = cooldown;

  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values,
  } as TerraformResource;

  return { projectName: 'test-project', resource, allResources: [resource] };
}

function run(cooldown: unknown) {
  const context = buildContext(cooldown);
  const adapter = factory.bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 REQ-05 (Terraform): negative default cooldown', () => {
  it('flags an Auto Scaling group with default_cooldown = -1', () => {
    const result = run(-1);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
  });

  it('flags an Auto Scaling group with default_cooldown = "-1" written as a string', () => {
    const result = run('-1');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: nearest input that flips the verdict — a valid, positive
  // cooldown duration. Primary behavior for the positive case is owned by the
  // "nonzero cooldown configured" requirement.
  it('does not flag an Auto Scaling group with default_cooldown = 300', () => {
    expect(run(300)).toBeNull();
    expect(run('300')).toBeNull();
  });
});
