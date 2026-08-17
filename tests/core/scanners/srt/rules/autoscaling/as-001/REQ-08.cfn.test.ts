import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';

function buildContext(cooldown: unknown): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      Cooldown: cooldown,
    },
  } as unknown as Resource;

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(cooldown: unknown): ScanResult | null {
  const context = buildContext(cooldown);
  const adapter = new As001CfnAdapterFactory().bind(context) as As001Adapter;
  return as001Control.run(adapter, context);
}

describe('AS-001 (CloudFormation): default cooldown holding non-numeric text', () => {
  // Primary behavior owned by AS-001: a cooldown that is not a number of seconds
  // cannot satisfy the requirement for a nonzero cooldown period, so it is flagged.
  it('flags an Auto Scaling group whose Cooldown is non-numeric text', () => {
    const result = scan('soon');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.priority).toBe('HIGH');
    expect(result?.fix).toBeTruthy();
  });

  it('flags an Auto Scaling group whose Cooldown is text with a numeric prefix but trailing units', () => {
    const result = scan('300 seconds');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: same property present, but it does hold a nonzero number of
  // seconds (as the numeric string CloudFormation commonly carries), so no finding.
  it('does not flag an Auto Scaling group whose Cooldown is a nonzero numeric string', () => {
    expect(scan('300')).toBeNull();
  });
});
