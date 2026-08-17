import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-05 (AS-001): an Auto Scaling group whose default cooldown is negative
// (e.g. -1 seconds) describes no waiting period at all, so it must be flagged.

const factory = new As001CfnAdapterFactory();

function buildContext(cooldown: unknown): CfnContext {
  const properties: Record<string, unknown> = {
    MinSize: '1',
    MaxSize: '3',
    AvailabilityZones: ['us-east-1a'],
  };
  if (cooldown !== undefined) properties['Cooldown'] = cooldown;

  const template = {
    Resources: {
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: properties,
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, any>)['Asg'],
    logicalId: 'Asg',
  };
}

function run(cooldown: unknown) {
  const context = buildContext(cooldown);
  const adapter = factory.bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 REQ-05 (CloudFormation): negative default cooldown', () => {
  it('flags an Auto Scaling group with a negative numeric Cooldown of -1', () => {
    const result = run(-1);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.resourceName).toBe('Asg');
  });

  it('flags an Auto Scaling group with a negative string Cooldown of "-1"', () => {
    const result = run('-1');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: nearest input that flips the verdict — a valid, positive
  // cooldown duration. Primary behavior for the positive case is owned by the
  // "nonzero cooldown configured" requirement.
  it('does not flag an Auto Scaling group with a positive Cooldown of 300 seconds', () => {
    expect(run(300)).toBeNull();
    expect(run('300')).toBeNull();
  });
});
