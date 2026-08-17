import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK = 'as-001-req-09-stack';
const LOGICAL_ID = 'AppAsg';

/**
 * Builds a template where a simple scaling policy attached to the group declares
 * its own nonzero Cooldown. The group's own Cooldown is supplied by the caller so
 * only that one property differs between the cases below.
 */
function buildTemplate(groupProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          ...groupProperties,
        },
      },
      ScaleOutPolicy: {
        Type: 'AWS::AutoScaling::ScalingPolicy',
        Properties: {
          // !Ref AppAsg resolves to the logical id string after preprocessing
          AutoScalingGroupName: LOGICAL_ID,
          AdjustmentType: 'ChangeInCapacity',
          PolicyType: 'SimpleScaling',
          ScalingAdjustment: 1,
          Cooldown: '120',
        },
      },
    },
  } as unknown as Template;
}

function evaluate(template: Template) {
  const resource = (template.Resources as Record<string, any>)[LOGICAL_ID];
  const context: CfnContext = { stackName: STACK, template, resource, logicalId: LOGICAL_ID };
  const adapter = new As001CfnAdapterFactory().bind(context) as As001Adapter;
  return { adapter, result: as001Control.run(adapter, context) };
}

describe('AS-001 CloudFormation - REQ-09: group omits its own default cooldown while a simple scaling policy sets one', () => {
  it('does not flag the group when Cooldown is omitted and the attached simple scaling policy declares a nonzero cooldown', () => {
    // Primary behaviour owned by this requirement: an omitted group Cooldown still
    // runs with the nonzero service default of 300 seconds, so the rule passes.
    const { adapter, result } = evaluate(buildTemplate({}));

    expect(adapter.cooldownState).toBe('absent');
    expect(result).toBeNull();
  });

  it('opposite case: flags the group when it explicitly sets its own Cooldown to zero despite the policy cooldown', () => {
    // Nearest input that flips the verdict: the group's own cooldown is present but zero.
    const { adapter, result } = evaluate(buildTemplate({ Cooldown: '0' }));

    expect(adapter.cooldownState).toBe('zero');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
