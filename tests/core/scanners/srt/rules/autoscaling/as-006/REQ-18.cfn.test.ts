import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006CfnAdapterFactory();

/**
 * Builds the template as it looks AFTER parseCfnTemplate: a `!Ref SubnetB` inside
 * VPCZoneIdentifier has already collapsed to the logical id string "SubnetB".
 */
function buildTemplate(groupProperties: Record<string, unknown>, subnetZone: string): Template {
  return {
    Resources: {
      AsgGroup: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '2',
          ...groupProperties,
        },
      },
      SubnetB: {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: 'MyVpc',
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: subnetZone,
        },
      },
    },
  } as unknown as Template;
}

function scan(template: Template): ScanResult | null {
  const resources = template.Resources as unknown as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['AsgGroup'],
    logicalId: 'AsgGroup',
  };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 CloudFormation - one named Availability Zone plus a single subnet in a different zone', () => {
  // Primary behavior owned by AS-006: one named AZ plus one subnet is single-zone
  // capacity on either dimension, and a subnet outside the named zone is invalid
  // rather than a second usable zone.
  it('flags an Auto Scaling group naming one Availability Zone and one subnet assigned to a different Availability Zone', () => {
    const template = buildTemplate(
      {
        AvailabilityZones: ['us-east-1a'],
        VPCZoneIdentifier: ['SubnetB'],
      },
      'us-east-1b',
    );

    const result = scan(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('AsgGroup');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest configuration that genuinely spans two zones -
  // two named Availability Zones with the subnet residing in one of them.
  it('does not flag an Auto Scaling group naming two Availability Zones with its subnet inside one of them', () => {
    const template = buildTemplate(
      {
        AvailabilityZones: ['us-east-1a', 'us-east-1b'],
        VPCZoneIdentifier: ['SubnetB'],
      },
      'us-east-1b',
    );

    expect(scan(template)).toBeNull();
  });
});
