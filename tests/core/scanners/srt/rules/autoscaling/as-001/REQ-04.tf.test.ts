import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import type { As001Adapter, CooldownState } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ADDRESS = 'aws_autoscaling_group.app';
const RESOURCE_TYPE = 'aws_autoscaling_group';

function buildResource(defaultCooldown: unknown): TerraformResource {
  return {
    type: RESOURCE_TYPE,
    name: 'app',
    address: ADDRESS,
    values: {
      min_size: 1,
      max_size: 3,
      default_cooldown: defaultCooldown,
    },
  } as unknown as TerraformResource;
}

function buildContext(defaultCooldown: unknown): TfContext {
  const resource = buildResource(defaultCooldown);
  return {
    projectName: 'asg-project',
    resource,
    allResources: [resource],
  };
}

function buildAdapter(cooldownState: CooldownState): As001Adapter {
  return {
    resourceId: ADDRESS,
    resourceType: RESOURCE_TYPE,
    cooldownState,
  };
}

describe('AS-001 Terraform: default cooldown period configured', () => {
  // Primary behavior owned by AS-001 / REQ-04: an explicitly configured nonzero
  // default_cooldown (300 seconds) satisfies the rule.
  it('passes when the Auto Scaling group sets default_cooldown to 300 seconds', () => {
    const context = buildContext(300);

    const result = as001Control.run(buildAdapter('nonzero'), context);

    expect(result).toBeNull();
  });

  // Opposite outcome: default_cooldown is still present and explicitly configured,
  // but it is zero, failing the nonzero standard the requirement turns on.
  it('flags the Auto Scaling group when default_cooldown is explicitly zero', () => {
    const context = buildContext(0);

    const result = as001Control.run(buildAdapter('zero'), context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe(ADDRESS);
    expect(result!.resourceType).toBe(RESOURCE_TYPE);
  });
});
