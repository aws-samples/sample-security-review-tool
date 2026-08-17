import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006CfnAdapterFactory();

/**
 * Builds a template where the Auto Scaling group names no AvailabilityZones and
 * places instances via VPCZoneIdentifier referencing two subnets in the template.
 * `!Ref SubnetX` resolves to the logical id string "SubnetX" during preprocessing.
 */
function buildTemplate(zoneA: string, zoneB: string): Template {
  return {
    Resources: {
      SubnetA: {
        Type: 'AWS::EC2::Subnet',
        Properties: { VpcId: 'Vpc', CidrBlock: '10.0.1.0/24', AvailabilityZone: zoneA },
      },
      SubnetB: {
        Type: 'AWS::EC2::Subnet',
        Properties: { VpcId: 'Vpc', CidrBlock: '10.0.2.0/24', AvailabilityZone: zoneB },
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

function run(template: Template): ScanResult | null {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, never>)['Asg'],
    logicalId: 'Asg',
  };
  return as006Control.run(factory.bind(context) as As006Adapter, context);
}

describe('AS-006 CloudFormation: subnets resolving to a single Availability Zone', () => {
  // Primary behavior owned by AS-006: two subnets, same AvailabilityZone, no AvailabilityZones listed.
  it('flags an Auto Scaling group whose two referenced subnets are both in the same Availability Zone', () => {
    const result = run(buildTemplate('us-east-1a', 'us-east-1a'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Nearest input that flips the verdict: identical template, one subnet moved to another zone.
  it('does not flag when the two referenced subnets are in different Availability Zones', () => {
    const result = run(buildTemplate('us-east-1a', 'us-east-1b'));

    expect(result).toBeNull();
  });
});
