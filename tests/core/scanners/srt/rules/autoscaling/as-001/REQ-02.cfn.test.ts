import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'MyAsg';

function buildTemplate(properties: Record<string, unknown>): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          ...properties,
        },
      } as unknown as Resource,
    },
  } as unknown as Template;
}

function scan(properties: Record<string, unknown>): ScanResult | null {
  const template = buildTemplate(properties);
  const resource = (template.Resources as Record<string, Resource>)[LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const factory = new As001CfnAdapterFactory();
  expect(factory.appliesTo('AWS::AutoScaling::AutoScalingGroup')).toBe(true);
  const adapter = factory.bind(context);
  return as001Control.run(adapter as never, context);
}

describe('AS-001 CloudFormation: Auto Scaling group specifies a default cooldown of 0 seconds', () => {
  // Primary behavior owned by AS-001: an explicit zero cooldown is not a configured nonzero cooldown.
  it('flags an Auto Scaling group with a numeric Cooldown of 0', () => {
    const result = scan({ Cooldown: 0 });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  it('flags an Auto Scaling group with a string Cooldown of "0"', () => {
    const result = scan({ Cooldown: '0' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: the nearest input that flips the verdict — cooldown still present, but nonzero.
  it('does not flag an Auto Scaling group with a nonzero Cooldown of 300', () => {
    expect(scan({ Cooldown: '300' })).toBeNull();
    expect(scan({ Cooldown: 300 })).toBeNull();
  });
});
