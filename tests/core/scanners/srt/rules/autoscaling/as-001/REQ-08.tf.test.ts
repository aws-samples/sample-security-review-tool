import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildResource(cooldown: unknown): TerraformResource {
  return {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 3,
      default_cooldown: cooldown,
      launch_template: [{ id: 'aws_launch_template.lt' }],
    },
  } as unknown as TerraformResource;
}

function scan(cooldown: unknown): ScanResult | null {
  const resource = buildResource(cooldown);
  const context: TfContext = { projectName: 'test-project', resource, allResources: [resource] };
  const adapter = new As001TfAdapterFactory().bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 (Terraform): default_cooldown holding non-numeric text', () => {
  // Primary behavior owned by AS-001: a cooldown that is not a number of seconds
  // cannot satisfy the requirement for a nonzero cooldown period, so it is flagged.
  it('flags an Auto Scaling group whose default_cooldown is non-numeric text', () => {
    const result = scan('soon');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toBeTruthy();
  });

  it('flags an Auto Scaling group whose default_cooldown is text with a numeric prefix but trailing units', () => {
    const result = scan('300s');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: same argument present, but it does hold a nonzero number of
  // seconds, so no finding.
  it('does not flag an Auto Scaling group whose default_cooldown is a nonzero number', () => {
    expect(scan(300)).toBeNull();
  });
});
