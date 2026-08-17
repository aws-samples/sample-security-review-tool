import { describe, expect, it } from 'vitest';
import { as006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.control.js';
import { As006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-006/as-006.adapter.cfn.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (AS-006): An Auto Scaling group whose only zone source is a single subnet
 * defined in the same template, with no AvailabilityZones listed, spans exactly one
 * Availability Zone and must be flagged.
 */

const factory = new As006CfnAdapterFactory();

function buildTemplate(vpcZoneIdentifier: unknown, subnetLogicalIds: string[]): Template {
  const resources: Record<string, unknown> = {
    Asg: {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '2',
        // Note: no AvailabilityZones property at all.
        VPCZoneIdentifier: vpcZoneIdentifier,
      },
    },
  };
  subnetLogicalIds.forEach((id, index) => {
    resources[id] = {
      Type: 'AWS::EC2::Subnet',
      Properties: {
        VpcId: 'Vpc',
        CidrBlock: `10.0.${index}.0/24`,
        // Distinct Availability Zone per subnet.
        AvailabilityZone: index === 0 ? 'us-east-1a' : 'us-east-1b',
      },
    };
  });
  return { Resources: resources } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resource = (template.Resources as Record<string, never>)['Asg'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as006Control.run(factory.bind(context), context);
}

describe('AS-006 CloudFormation - REQ-07 single subnet, no Availability Zones', () => {
  it('flags an Auto Scaling group whose only placement is one subnet defined in the template', () => {
    // !Ref SubnetA resolves to the logical id string after preprocessing.
    const result = run(buildTemplate(['SubnetA'], ['SubnetA']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.resourceName).toBe('Asg');
  });

  it('flags a single subnet supplied as a one-entry comma separated string', () => {
    const result = run(buildTemplate('SubnetA', ['SubnetA']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-006');
  });

  // Opposite outcome: nearest input that flips the verdict is a second subnet in
  // another Availability Zone. Coverage of multi-subnet placement belongs to the
  // primary "spans two zones" requirement; asserted here only to discriminate.
  it('does not flag an Auto Scaling group referencing two subnets in different Availability Zones', () => {
    const result = run(buildTemplate(['SubnetA', 'SubnetB'], ['SubnetA', 'SubnetB']));

    expect(result).toBeNull();
  });
});
