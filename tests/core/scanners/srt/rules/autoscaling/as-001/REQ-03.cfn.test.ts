import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As001CfnAdapterFactory();

function scan(properties: Record<string, unknown>) {
  const template = {
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: properties,
      },
    },
  } as unknown as Template;

  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['Asg'],
    logicalId: 'Asg',
  };

  return as001Control.run(factory.bind(context), context);
}

// REQ-03 (AS-001): a default cooldown of 1 second is a configured nonzero value and must pass.
describe('AS-001 CloudFormation — smallest nonzero default cooldown', () => {
  it('does not flag an Auto Scaling group with a numeric Cooldown of 1 second', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      Cooldown: 1,
    });

    expect(result).toBeNull();
  });

  it('does not flag an Auto Scaling group with a string Cooldown of "1" second', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      Cooldown: '1',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same template, cooldown lowered to zero — the only value the rule forbids.
  it('flags an Auto Scaling group whose Cooldown is zero seconds', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      Cooldown: 0,
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('AS-001');
    expect(result!.resourceName).toBe('Asg');
  });
});
