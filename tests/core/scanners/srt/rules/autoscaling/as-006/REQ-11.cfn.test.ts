import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { As006Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As006CfnAdapterFactory();

/**
 * Builds a template whose Auto Scaling group references three in-template subnets.
 * `!Ref SubnetX` resolves to the logical ID string after preprocessing, so the
 * VPCZoneIdentifier entries are the logical IDs themselves.
 */
function buildTemplate(zones: [string, string, string]): Template {
  return {
    Resources: {
      SubnetA: { Type: 'AWS::EC2::Subnet', Properties: { VpcId: 'Vpc', CidrBlock: '10.0.0.0/24', AvailabilityZone: zones[0] } },
      SubnetB: { Type: 'AWS::EC2::Subnet', Properties: { VpcId: 'Vpc', CidrBlock: '10.0.1.0/24', AvailabilityZone: zones[1] } },
      SubnetC: { Type: 'AWS::EC2::Subnet', Properties: { VpcId: 'Vpc', CidrBlock: '10.0.2.0/24', AvailabilityZone: zones[2] } },
      Asg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '2',
          MaxSize: '4',
          VPCZoneIdentifier: ['SubnetA', 'SubnetB', 'SubnetC'],
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template): CfnContext {
  const resources = template.Resources as Record<string, any>;
  return { stackName: 'test-stack', template, resource: resources.Asg, logicalId: 'Asg' };
}

function evaluate(template: Template) {
  const context = contextFor(template);
  const adapter = factory.bind(context) as As006Adapter;
  return as006Control.run(adapter, context);
}

describe('AS-006 CloudFormation: subnet-derived Availability Zone coverage', () => {
  // Primary behavior for this requirement: three subnets covering two distinct zones passes.
  it('passes when three referenced subnets resolve to two distinct Availability Zones', () => {
    const result = evaluate(buildTemplate(['us-east-1a', 'us-east-1a', 'us-east-1b']));
    expect(result).toBeNull();
  });

  // Opposite outcome: same three-subnet shape, but every subnet sits in one zone.
  it('flags the group when all three referenced subnets resolve to a single Availability Zone', () => {
    const result = evaluate(buildTemplate(['us-east-1a', 'us-east-1a', 'us-east-1a']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
