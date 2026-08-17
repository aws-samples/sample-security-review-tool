import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'as-006-stack';
const LOGICAL_ID = 'AsgResource';
const factory = new As006CfnAdapterFactory();

function scan(template: Template) {
  const resources = template.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource: resources[LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
  return as006Control.run(factory.bind(context), context);
}

/**
 * REQ-16 owns this behavior: when the Auto Scaling group's subnet list is supplied at
 * deployment time (an unresolved intrinsic), the number of subnets and the Availability
 * Zones they sit in are unknown, so no breach can be asserted.
 */
describe('AS-006 CloudFormation - subnet list supplied at deployment time', () => {
  it('passes when the subnet list comes entirely from a deploy-time input and no Availability Zones are named', () => {
    const template = {
      Parameters: {
        SubnetIds: { Type: 'String' },
      },
      Resources: {
        [LOGICAL_ID]: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            // Fn::Split is not resolved by preprocessing: the subnet list is unknown here.
            VPCZoneIdentifier: { 'Fn::Split': [',', 'DEFAULT'] },
          },
        },
      },
    } as unknown as Template;

    expect(scan(template)).toBeNull();
  });

  // Opposite outcome: same shape, but the subnet list is known at analysis time and
  // pins the group to a single Availability Zone (owned by the single-subnet scenario).
  it('flags a group whose subnet list is known and names only one subnet', () => {
    const template = {
      Resources: {
        PrivateSubnetA: {
          Type: 'AWS::EC2::Subnet',
          Properties: { AvailabilityZone: 'us-east-1a', CidrBlock: '10.0.1.0/24', VpcId: 'Vpc' },
        },
        [LOGICAL_ID]: {
          Type: 'AWS::AutoScaling::AutoScalingGroup',
          Properties: {
            MinSize: '2',
            MaxSize: '4',
            VPCZoneIdentifier: ['PrivateSubnetA'],
          },
        },
      },
    } as unknown as Template;

    const result = scan(template);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
