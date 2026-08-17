import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (AS-001): An Auto Scaling group whose default cooldown comes from a
 * deployment-time template parameter that declares no value must NOT be flagged.
 * A parameter with no Default resolves to the string "DEFAULT" after
 * preprocessing, so the real cooldown is unknowable at analysis time.
 */

const factory = new As001CfnAdapterFactory();

function buildContext(cooldown: unknown): CfnContext {
  const template = {
    Parameters: {
      CooldownSeconds: { Type: 'Number' },
    },
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          Cooldown: cooldown,
        },
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['Asg'],
    logicalId: 'Asg',
  };
}

function run(cooldown: unknown) {
  const context = buildContext(cooldown);
  const adapter = factory.bind(context);
  return as001Control.run(adapter, context);
}

describe('AS-001 CloudFormation — cooldown from a parameter with no declared value', () => {
  it('applies to Auto Scaling groups', () => {
    expect(factory.appliesTo('AWS::AutoScaling::AutoScalingGroup')).toBe(true);
  });

  // Primary behavior owned by this requirement (REQ-06).
  it('does not flag a group whose Cooldown came from a parameter with no value (resolves to "DEFAULT")', () => {
    expect(run('DEFAULT')).toBeNull();
  });

  // Opposite outcome: same property present, but a known breaching value.
  it('flags a group whose Cooldown is a known zero value', () => {
    const result = run(0);
    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe('Asg');
  });
});
