import { describe, expect, it } from 'vitest';

import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function run(properties: Record<string, unknown>): ScanResult | null {
  const context = buildContext(properties);
  const adapter = new As006CfnAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 (CloudFormation) - Auto Scaling groups must span at least two Availability Zones', () => {
  // Primary behavior owned by this requirement: exactly one AZ named, no subnets referenced -> flag.
  it('flags an Auto Scaling group that names exactly one Availability Zone and references no subnets', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict - a second Availability Zone.
  it('does not flag an Auto Scaling group that names two Availability Zones and references no subnets', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a', 'us-east-1b'],
    });

    expect(result).toBeNull();
  });
});
