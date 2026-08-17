import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import type { As001Adapter, CooldownState } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';
const RESOURCE_TYPE = 'AWS::AutoScaling::AutoScalingGroup';

function buildTemplate(cooldown: unknown): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: RESOURCE_TYPE,
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          Cooldown: cooldown,
        },
      },
    },
  } as unknown as Template;
}

function buildContext(cooldown: unknown): CfnContext {
  const template = buildTemplate(cooldown);
  return {
    stackName: 'AsgStack',
    template,
    resource: template.Resources![LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
}

function buildAdapter(cooldownState: CooldownState): As001Adapter {
  return {
    resourceId: LOGICAL_ID,
    resourceType: RESOURCE_TYPE,
    cooldownState,
  };
}

describe('AS-001 CloudFormation: default cooldown period configured', () => {
  // Primary behavior owned by AS-001 / REQ-04: an explicitly configured nonzero
  // default cooldown (300 seconds) satisfies the rule.
  it('passes when the Auto Scaling group sets a default cooldown of 300 seconds', () => {
    const context = buildContext('300');

    const result = as001Control.run(buildAdapter('nonzero'), context);

    expect(result).toBeNull();
  });

  // Opposite outcome: the value is still present and explicitly configured, but it
  // is zero, which fails the nonzero standard the requirement turns on.
  it('flags the Auto Scaling group when the configured default cooldown is zero seconds', () => {
    const context = buildContext('0');

    const result = as001Control.run(buildAdapter('zero'), context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe(LOGICAL_ID);
    expect(result!.resourceType).toBe(RESOURCE_TYPE);
  });
});
