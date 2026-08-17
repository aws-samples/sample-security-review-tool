import { describe, expect, it } from 'vitest';

import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::AutoScaling::AutoScalingGroup';
const LOGICAL_ID = 'WebAsg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = { Type: RESOURCE_TYPE, Properties: properties } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As006CfnAdapterFactory().bind(context);
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation - group names two Availability Zones and no subnets', () => {
  // Primary behavior owned by this requirement: two distinct AZs listed, no VPCZoneIdentifier -> compliant.
  it('passes when AvailabilityZones lists two distinct zones and no subnets are referenced', () => {
    const result = scan({
      AvailabilityZones: ['us-east-1a', 'us-east-1b'],
      MinSize: '2',
      MaxSize: '4',
    });

    expect(result).toBeNull();
  });

  it('passes when AvailabilityZones lists more than two distinct zones and no subnets are referenced', () => {
    const result = scan({
      AvailabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
      MinSize: '2',
      MaxSize: '6',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: same shape, but only one zone named -> the multi-AZ span is not met.
  it('flags a group that names only one Availability Zone and no subnets', () => {
    const result = scan({
      AvailabilityZones: ['us-east-1a'],
      MinSize: '2',
      MaxSize: '4',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });
});
