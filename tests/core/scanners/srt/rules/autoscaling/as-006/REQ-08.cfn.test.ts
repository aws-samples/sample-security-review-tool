import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006CfnAdapterFactory();

function scan(properties: Record<string, unknown>): ScanResult | null {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 CloudFormation — empty subnet reference list with no Availability Zones', () => {
  // Primary behaviour owned by this requirement: an empty VPCZoneIdentifier list
  // supplies zero subnets, and with no AvailabilityZones the group cannot span two AZs.
  it('flags an Auto Scaling group whose VPCZoneIdentifier is present but empty and names no Availability Zones', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      VPCZoneIdentifier: [],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: same shape, but the subnet list actually carries two subnets,
  // which satisfies the two-AZ minimum, so nothing is flagged.
  it('does not flag an Auto Scaling group whose subnet reference list carries two subnets', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      VPCZoneIdentifier: ['SubnetA', 'SubnetB'],
    });

    expect(result).toBeNull();
  });
});
