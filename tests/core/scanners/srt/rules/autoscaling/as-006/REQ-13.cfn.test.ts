import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006CfnAdapterFactory();

function scan(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources as Record<string, Resource>)[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as unknown as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation: subnets whose Availability Zones are not knowable at analysis time', () => {
  // Primary behaviour owned by REQ-13: two literal, pre-existing subnet IDs -> zones unknown -> no finding.
  it('passes an Auto Scaling group that lists two literal subnet IDs not defined in the template', () => {
    const template = {
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            VPCZoneIdentifier: ['subnet-0aa11bb22cc33dd44', 'subnet-0ee55ff66gg77hh88'],
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'Asg')).toBeNull();
  });

  it('passes when the two literal, undefined subnet IDs are given as a comma-separated string', () => {
    const template = {
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            VPCZoneIdentifier: 'subnet-0aa11bb22cc33dd44,subnet-0ee55ff66gg77hh88',
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'Asg')).toBeNull();
  });

  // Opposite outcome: same two-subnet shape, but the subnets ARE defined in the template and share one zone.
  it('flags an Auto Scaling group whose two in-template subnets both sit in the same Availability Zone', () => {
    const template = {
      Resources: {
        SubnetOne: {
          Type: 'AWS::EC2::Subnet',
          Properties: { VpcId: 'Vpc', CidrBlock: '10.0.1.0/24', AvailabilityZone: 'us-east-1a' },
        },
        SubnetTwo: {
          Type: 'AWS::EC2::Subnet',
          Properties: { VpcId: 'Vpc', CidrBlock: '10.0.2.0/24', AvailabilityZone: 'us-east-1a' },
        },
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            // !Ref SubnetOne / !Ref SubnetTwo resolve to the logical IDs after preprocessing.
            VPCZoneIdentifier: ['SubnetOne', 'SubnetTwo'],
          },
        },
      },
    } as unknown as Template;

    const result = scan(template, 'Asg');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
