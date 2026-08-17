import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.tf.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (AS-001): `default_cooldown = var.cooldown` where the variable is
 * declared in the same .tf file with a nonzero default resolves at analysis
 * time to that number, so the group runs with a nonzero cooldown.
 */
function run(resolvedCooldown: unknown): ScanResult | null {
  const resource: TerraformResource = {
    type: 'aws_autoscaling_group',
    name: 'app',
    address: 'aws_autoscaling_group.app',
    values: {
      min_size: 1,
      max_size: 3,
      // Authored as var.cooldown; the reader substitutes the same-file default.
      default_cooldown: resolvedCooldown,
    },
  } as unknown as TerraformResource;

  const context: TfContext = {
    projectName: 'as-001-project',
    resource,
    allResources: [resource],
  };
  const adapter = new As001TfAdapterFactory().bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 Terraform — cooldown from a variable default', () => {
  it('passes when the variable default resolves to a nonzero cooldown', () => {
    expect(run(300)).toBeNull();
  });

  // Opposite outcome: same variable reference, default resolves to zero, which
  // is the zero-cooldown breach owned by AS-001.
  it('flags when the variable default resolves to a zero cooldown', () => {
    const result = run(0);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('aws_autoscaling_group.app');
    expect(result?.resourceType).toBe('aws_autoscaling_group');
  });
});
