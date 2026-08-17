import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * AS-006: Auto Scaling groups must span at least two Availability Zones.
 *
 * Requirement under test (primary behavior owned by AS-006): when one of the group's
 * Availability Zone entries comes from a deployment-time input, the second zone's identity
 * is not knowable at analysis time, so no breach can be asserted.
 *
 * Templates below are written as they appear AFTER parseCfnTemplate: a `!Ref` to a
 * parameter with no default resolves to the literal string "DEFAULT".
 */

const LOGICAL_ID = 'AppAsg';

function buildTemplate(availabilityZones: unknown[]): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '2',
          MaxSize: '4',
          AvailabilityZones: availabilityZones,
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resource = (template.Resources as Record<string, never>)[LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new As006CfnAdapterFactory().bind(context);
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation: zone list mixes a literal Availability Zone with a deployment-time input', () => {
  it('does not report a finding when the second zone entry is supplied at deployment time and no subnets are referenced', () => {
    const result = runControl(buildTemplate(['us-east-1a', 'DEFAULT']));

    expect(result).toBeNull();
  });

  // Opposite outcome: same shape, but the second entry is a known duplicate of the first,
  // so the group is provably confined to a single Availability Zone.
  it('reports a finding when the second zone entry is a known duplicate of the first zone', () => {
    const result = runControl(buildTemplate(['us-east-1a', 'us-east-1a']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
