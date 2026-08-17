import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::AutoScaling::AutoScalingGroup';
const LOGICAL_ID = 'Asg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = { Type: RESOURCE_TYPE, Properties: properties } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(properties: Record<string, unknown>): ScanResult | null {
  const context = buildContext(properties);
  const adapter = new As006CfnAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation: empty Availability Zones list with no subnets', () => {
  // Primary behaviour owned by this requirement: an empty zone list and no
  // VPC zone identifier means zero zones, which cannot span two zones.
  it('flags an Auto Scaling group whose AvailabilityZones list is present but empty and has no VPCZoneIdentifier', () => {
    const result = run({
      AvailabilityZones: [],
      MinSize: '1',
      MaxSize: '2',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });

  // Opposite outcome: the nearest input that flips the verdict — the same group
  // with the zone list populated with two zones must not be flagged.
  it('does not flag the same group when the AvailabilityZones list holds two zones', () => {
    const result = run({
      AvailabilityZones: ['us-east-1a', 'us-east-1b'],
      MinSize: '1',
      MaxSize: '2',
    });

    expect(result).toBeNull();
  });
});
