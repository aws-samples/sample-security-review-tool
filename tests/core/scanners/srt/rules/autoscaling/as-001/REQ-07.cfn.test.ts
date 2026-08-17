import { describe, expect, it } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { As001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';
const RESOURCE_TYPE = 'AWS::AutoScaling::AutoScalingGroup';

function buildContext(cooldown: unknown): CfnContext {
  const resource = {
    Type: RESOURCE_TYPE,
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
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

describe('AS-001 CloudFormation - Cooldown present but holding an empty text value', () => {
  // Primary behavior owned by this requirement: an empty string supplies no
  // parsable number of seconds, so the group has no usable cooldown setting.
  it('flags an Auto Scaling group whose Cooldown is an empty string', () => {
    const result = scan('');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });

  it('flags an Auto Scaling group whose Cooldown is a whitespace-only string', () => {
    const result = scan('   ');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
  });

  // Opposite outcome: the nearest input that flips the verdict - the same
  // property, still present as a string, but carrying a parsable nonzero value.
  it('does not flag an Auto Scaling group whose Cooldown is a nonzero numeric string', () => {
    expect(scan('300')).toBeNull();
  });
});
