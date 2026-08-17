import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (AS-001): Auto Scaling Groups must have a default cooldown period configured
 * (set to a nonzero value).
 *
 * Scenario: the group's Cooldown references a template Parameter whose declared Default is zero
 * and no value is supplied at deployment. After template preprocessing a `Ref` to such a parameter
 * resolves to the parameter's default, so the rule sees Cooldown === 0 — an explicitly disabled
 * cooldown, which the rule prohibits.
 */

const factory = new As001CfnAdapterFactory();

function buildContext(cooldown: unknown): CfnContext {
  // Post-preprocessing shape: `!Ref CooldownSeconds` has already been replaced by the
  // parameter's Default value.
  const template = {
    Parameters: {
      CooldownSeconds: { Type: 'Number', Default: cooldown },
    },
    Resources: {
      AppAsg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          Cooldown: cooldown,
        },
      },
    },
  } as unknown as Template;

  const resource = (template.Resources as Record<string, unknown>)['AppAsg'] as CfnContext['resource'];
  return { stackName: 'asg-stack', template, resource, logicalId: 'AppAsg' };
}

function run(cooldown: unknown) {
  const context = buildContext(cooldown);
  return as001Control.run(factory.bind(context), context);
}

describe('AS-001 CloudFormation - cooldown from a parameter defaulting to zero', () => {
  it('flags the group when the referenced parameter default resolves to zero', () => {
    const result = run(0);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('AppAsg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.issue).toMatch(/zero/i);
  });

  it('flags the group when the parameter default resolves to the string "0"', () => {
    const result = run('0');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: nearest input that flips the verdict — the parameter still supplies the
  // cooldown, but its default is a usable nonzero duration.
  it('does not flag the group when the referenced parameter default resolves to a nonzero value', () => {
    expect(run(300)).toBeNull();
  });
});
