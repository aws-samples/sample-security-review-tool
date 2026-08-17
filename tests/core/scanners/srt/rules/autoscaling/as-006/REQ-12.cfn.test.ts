import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'as-006-stack';
const ASG_ID = 'AsgWithZoneIdSubnets';

/**
 * Builds a template where the group's VPC zone identifier points at two subnets
 * declared in the same template, each expressing placement with an AZ ID
 * (AvailabilityZoneId) rather than an AZ name.
 * Values are written post-preprocessing: `!Ref SubnetA` resolves to "SubnetA".
 */
function buildTemplate(zoneIdA: string, zoneIdB: string): Template {
  return {
    Resources: {
      SubnetA: {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: 'Vpc',
          CidrBlock: '10.0.1.0/24',
          AvailabilityZoneId: zoneIdA,
        },
      },
      SubnetB: {
        Type: 'AWS::EC2::Subnet',
        Properties: {
          VpcId: 'Vpc',
          CidrBlock: '10.0.2.0/24',
          AvailabilityZoneId: zoneIdB,
        },
      },
      [ASG_ID]: {
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
  const resources = (template as unknown as { Resources: Record<string, never> }).Resources;
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource: resources[ASG_ID],
    logicalId: ASG_ID,
  };
  const adapter = new As006CfnAdapterFactory().bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation: subnets whose placement is expressed as AZ IDs', () => {
  // Primary behavior for this requirement: two differing AZ IDs are two distinct AZs.
  it('does not flag a group whose two subnets carry two different availability zone identifiers', () => {
    const result = run(buildTemplate('use1-az1', 'use1-az2'));

    expect(result).toBeNull();
  });

  // Opposite outcome: identical AZ IDs mean both subnets sit in one Availability Zone.
  it('flags a group whose two subnets carry the same availability zone identifier', () => {
    const result = run(buildTemplate('use1-az1', 'use1-az1'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(ASG_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.issue).toContain('same Availability Zone');
  });
});
