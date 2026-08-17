import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ADDRESS = 'aws_autoscaling_group.app';

function buildContext(cooldown: unknown): TfContext {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: ADDRESS,
    values: {
      min_size: 1,
      max_size: 3,
      default_cooldown: cooldown,
    },
  } as unknown as TerraformResource;

  return { projectName: 'test-project', resource, allResources: [resource] };
}

function scan(cooldown: unknown): ScanResult | null {
  const context = buildContext(cooldown);
  const adapter = new As001TfAdapterFactory().bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 Terraform - default_cooldown present but holding an empty text value', () => {
  // Primary behavior owned by this requirement: an empty string supplies no
  // parsable number of seconds, so the group has no usable cooldown setting.
  it('flags an Auto Scaling group whose default_cooldown is an empty string', () => {
    const result = scan('');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
    expect(result?.resourceName).toBe(ADDRESS);
  });

  it('flags an Auto Scaling group whose default_cooldown is a whitespace-only string', () => {
    const result = scan('  ');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same
  // argument, still present as a string, but carrying a parsable nonzero value.
  it('does not flag an Auto Scaling group whose default_cooldown is a nonzero numeric string', () => {
    expect(scan('300')).toBeNull();
  });
});
