import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As001TfAdapterFactory();

function scan(values: Record<string, unknown>) {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'asg',
    address: 'aws_autoscaling_group.asg',
    values,
  } as TerraformResource;

  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };

  return as001Control.run(factory.bind(context), context);
}

// REQ-03 (AS-001): a default cooldown of 1 second is a configured nonzero value and must pass.
describe('AS-001 Terraform — smallest nonzero default cooldown', () => {
  it('does not flag an Auto Scaling group with a numeric default_cooldown of 1 second', () => {
    const result = scan({
      max_size: 2,
      min_size: 1,
      default_cooldown: 1,
    });

    expect(result).toBeNull();
  });

  it('does not flag an Auto Scaling group with a string default_cooldown of "1" second', () => {
    const result = scan({
      max_size: 2,
      min_size: 1,
      default_cooldown: '1',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: identical resource with the cooldown lowered to zero, the only forbidden value.
  it('flags an Auto Scaling group whose default_cooldown is zero seconds', () => {
    const result = scan({
      max_size: 2,
      min_size: 1,
      default_cooldown: 0,
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe('aws_autoscaling_group.asg');
  });
});
