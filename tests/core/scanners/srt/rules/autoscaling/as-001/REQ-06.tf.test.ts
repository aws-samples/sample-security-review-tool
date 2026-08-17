import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (AS-001): An Auto Scaling group whose default_cooldown comes from an
 * input variable with no reachable value must NOT be flagged — the deployed
 * value is supplied at apply time and cannot be known by the scanner.
 */

const factory = new As001TfAdapterFactory();

function buildResource(values: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values: { min_size: 1, max_size: 3, ...values },
  } as unknown as TerraformResource;
}

function run(values: Record<string, unknown>) {
  const resource = buildResource(values);
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
  const adapter = factory.bind(context);
  return as001Control.run(adapter, context);
}

describe('AS-001 Terraform — cooldown from an input variable with no reachable value', () => {
  it('applies to aws_autoscaling_group', () => {
    expect(factory.appliesTo('aws_autoscaling_group')).toBe(true);
  });

  // Primary behavior owned by this requirement (REQ-06).
  it('does not flag a group whose default_cooldown is an unresolved variable reference', () => {
    expect(run({ default_cooldown: '__unresolved__:var.cooldown' })).toBeNull();
  });

  // Opposite outcome: same argument present, but a known breaching value.
  it('flags a group whose default_cooldown is a known zero value', () => {
    const result = run({ default_cooldown: 0 });
    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe('aws_autoscaling_group.asg');
  });
});
