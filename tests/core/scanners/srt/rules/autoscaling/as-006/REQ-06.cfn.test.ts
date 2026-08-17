import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'WebAsg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As006CfnAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 (CloudFormation) duplicate Availability Zone entries', () => {
  // Primary behavior owned by AS-006: two identical zone entries enable only one distinct AZ.
  it('flags an Auto Scaling group whose zone list repeats the same Availability Zone and has no subnets', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      AvailabilityZones: ['us-east-1a', 'us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict — same two-entry list, distinct zones.
  it('does not flag an Auto Scaling group whose two zone entries are different Availability Zones', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      AvailabilityZones: ['us-east-1a', 'us-east-1b'],
    });

    expect(result).toBeNull();
  });
});
