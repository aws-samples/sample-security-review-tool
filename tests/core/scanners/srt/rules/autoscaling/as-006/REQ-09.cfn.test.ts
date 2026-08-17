import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (AS-006): An Auto Scaling group that names no AvailabilityZones but whose
 * VPCZoneIdentifier lists two in-template subnets placed in DIFFERENT Availability
 * Zones spans two zones, and must pass.
 *
 * Fixtures are written post-preprocessing: `!Ref SubnetA` resolves to the literal
 * logical id string "SubnetA".
 */

const factory = new As006CfnAdapterFactory();

function buildTemplate(subnetAZones: [string, string]): Template {
  return {
    Resources: {
      SubnetA: {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: 'Vpc',
          CidrBlock: '10.0.1.0/24',
          AvailabilityZone: subnetAZones[0],
        },
      },
      SubnetB: {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: 'Vpc',
          CidrBlock: '10.0.2.0/24',
          AvailabilityZone: subnetAZones[1],
        },
      },
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '2',
          MaxSize: '4',
          VPCZoneIdentifier: ['SubnetA', 'SubnetB'],
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template) {
  const resource = (template.Resources as Record<string, any>)['Asg'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as006Control.run(factory.bind(context) as any, context);
}

describe('AS-006 CloudFormation — subnets across Availability Zones', () => {
  it('passes when two referenced subnets sit in different Availability Zones and no zones are named', () => {
    const result = run(buildTemplate(['us-east-1a', 'us-east-1b']));

    expect(result).toBeNull();
  });

  // Opposite outcome: same shape, but both subnets share one Availability Zone,
  // so the group does not span two zones. (Primary behavior owned by REQ-09.)
  it('flags when the two referenced subnets sit in the same Availability Zone', () => {
    const result = run(buildTemplate(['us-east-1a', 'us-east-1a']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });
});
