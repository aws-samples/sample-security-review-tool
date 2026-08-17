import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-20 (AS-006): An Auto Scaling group whose placement list holds exactly ONE entry is
 * confined to a single Availability Zone, even when that entry's zone is only known at
 * deployment time (preprocessing leaves the literal string "DEFAULT" for such inputs).
 * A subnet lives in exactly one AZ, so one subnet entry — or one zone entry — must be flagged.
 */

const factory = new As006CfnAdapterFactory();

function runControl(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return as006Control.run(factory.bind(context), context);
}

/** Subnet whose Availability Zone comes from a deployment-time input (resolves to "DEFAULT"). */
const deployTimeSubnet = (): Record<string, unknown> => ({
  Type: 'AWS::EC2::Subnet',
  Properties: { VpcId: 'Vpc', CidrBlock: '10.0.1.0/24', AvailabilityZone: 'DEFAULT' },
});

describe('AS-006 REQ-20 (CloudFormation): single-entry placement list is one Availability Zone', () => {
  it('flags a group whose VPCZoneIdentifier holds one subnet reference with a deployment-time zone', () => {
    const template = {
      Resources: {
        SubnetA: deployTimeSubnet(),
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '1',
            MaxSize: '2',
            VPCZoneIdentifier: ['SubnetA'],
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'Asg');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.resourceName).toBe('Asg');
  });

  it('flags a group whose VPCZoneIdentifier is a single literal subnet id', () => {
    const template = {
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '1',
            MaxSize: '2',
            VPCZoneIdentifier: 'subnet-0abc123',
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'Asg');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });

  it('flags a group whose AvailabilityZones list holds exactly one deployment-time entry', () => {
    const template = {
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '1',
            MaxSize: '2',
            AvailabilityZones: ['DEFAULT'],
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'Asg');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });

  // Opposite outcome: only the number of entries changes — two subnet entries can reach two
  // Availability Zones, so an unknown zone per subnet is not a breach.
  it('does not flag a group whose VPCZoneIdentifier holds two subnet references with deployment-time zones', () => {
    const template = {
      Resources: {
        SubnetA: deployTimeSubnet(),
        SubnetB: deployTimeSubnet(),
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '1',
            MaxSize: '2',
            VPCZoneIdentifier: ['SubnetA', 'SubnetB'],
          },
        },
      },
    } as unknown as Template;

    expect(runControl(template, 'Asg')).toBeNull();
  });

  // Opposite outcome on the zone side: two named zones satisfy the requirement.
  it('does not flag a group whose AvailabilityZones list holds two distinct zones', () => {
    const template = {
      Resources: {
        Asg: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '1',
            MaxSize: '2',
            AvailabilityZones: ['us-east-1a', 'us-east-1b'],
          },
        },
      },
    } as unknown as Template;

    expect(runControl(template, 'Asg')).toBeNull();
  });
});
