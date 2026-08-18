import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function scan(resource: Resource, logicalId = 'Asg'): ScanResult | null {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

/**
 * REQ-05 (AS-005): a mixed instances policy provisions exclusively from launch
 * templates — a base LaunchTemplateSpecification plus per-instance-type
 * overrides that each name their own launch template — so the group passes.
 */
describe('AS-005 CloudFormation — mixed instances policy with per-instance-type launch template overrides', () => {
  it('does not flag a group whose mixed instances policy has a base launch template and override launch templates', () => {
    const resource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '4',
        MixedInstancesPolicy: {
          LaunchTemplate: {
            LaunchTemplateSpecification: {
              LaunchTemplateId: 'BaseLaunchTemplate',
              Version: 'BaseLaunchTemplate',
            },
            Overrides: [
              {
                InstanceType: 'm5.large',
                LaunchTemplateSpecification: {
                  LaunchTemplateId: 'M5LaunchTemplate',
                  Version: 'M5LaunchTemplate',
                },
              },
              {
                InstanceType: 'c5.large',
                LaunchTemplateSpecification: {
                  LaunchTemplateId: 'C5LaunchTemplate',
                  Version: 'C5LaunchTemplate',
                },
              },
            ],
          },
        },
      },
    } as unknown as Resource;

    expect(scan(resource)).toBeNull();
  });

  // Opposite outcome: identical group except the instance configuration comes
  // from a launch configuration instead of the mixed instances policy.
  it('flags a group that names a launch configuration instead of a mixed instances policy', () => {
    const resource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '4',
        LaunchConfigurationName: 'LegacyLaunchConfiguration',
      },
    } as unknown as Resource;

    const result = scan(resource);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
