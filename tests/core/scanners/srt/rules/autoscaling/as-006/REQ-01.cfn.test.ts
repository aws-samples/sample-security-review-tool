import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: {
      Asg: resource,
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = factory.bind(context);
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation - REQ-01: neither AvailabilityZones nor VPCZoneIdentifier specified', () => {
  // Primary behavior owned by this requirement: no placement information at all -> flag.
  it('flags an Auto Scaling group that specifies neither AvailabilityZones nor VPCZoneIdentifier', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      LaunchConfigurationName: 'my-launch-config',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: placement is documented across two AZs, so the requirement is satisfied.
  it('does not flag an Auto Scaling group that specifies two Availability Zones', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      LaunchConfigurationName: 'my-launch-config',
      AvailabilityZones: ['us-east-1a', 'us-east-1b'],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome via the other placement mechanism: two subnets in the VPC zone identifier.
  it('does not flag an Auto Scaling group that specifies two subnets via VPCZoneIdentifier', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '3',
      LaunchConfigurationName: 'my-launch-config',
      VPCZoneIdentifier: ['SubnetA', 'SubnetB'],
    });

    expect(result).toBeNull();
  });
});
