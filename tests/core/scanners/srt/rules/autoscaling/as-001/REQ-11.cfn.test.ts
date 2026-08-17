import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const GROUP_ID = 'AppAsg';

/**
 * Template: an Auto Scaling group that sets its own default cooldown, plus a simple
 * scaling policy attached to that group which declares its own cooldown period.
 */
function buildTemplate(groupCooldown: unknown, policyCooldown: unknown): Template {
  return {
    Resources: {
      [GROUP_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          Cooldown: groupCooldown,
        },
      },
      ScaleOutPolicy: {
        Type: 'AWS::AutoScaling::ScalingPolicy',
        Properties: {
          // Ref to a resource resolves to the logical id string after preprocessing.
          AutoScalingGroupName: GROUP_ID,
          AdjustmentType: 'ChangeInCapacity',
          PolicyType: 'SimpleScaling',
          ScalingAdjustment: 1,
          Cooldown: policyCooldown,
        },
      },
    },
  } as unknown as Template;
}

function bind(template: Template): { adapter: As001Adapter; context: CfnContext } {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources![GROUP_ID],
    logicalId: GROUP_ID,
  };
  return { adapter: new As001CfnAdapterFactory().bind(context), context };
}

describe('AS-001 CloudFormation — group default cooldown of 0 alongside a policy-level cooldown', () => {
  // Primary behavior owned by AS-001: the group's own default cooldown must be nonzero.
  it('flags the group when its default cooldown is 0 even though the attached simple scaling policy sets a nonzero cooldown', () => {
    const { adapter, context } = bind(buildTemplate('0', '300'));

    const result = as001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe(GROUP_ID);
    expect(result!.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  it('flags the group when its numeric default cooldown is 0 with a nonzero policy cooldown', () => {
    const { adapter, context } = bind(buildTemplate(0, 300));

    expect(as001Control.run(adapter, context)).not.toBeNull();
  });

  // Opposite outcome: only the group's own default cooldown changes to a nonzero value.
  it('does not flag the group when its own default cooldown is nonzero while the policy cooldown is 0', () => {
    const { adapter, context } = bind(buildTemplate('300', '0'));

    expect(as001Control.run(adapter, context)).toBeNull();
  });
});
