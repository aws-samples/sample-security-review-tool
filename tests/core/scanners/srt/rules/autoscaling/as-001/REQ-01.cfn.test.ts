import { describe, it, expect } from 'vitest';
import { as001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.control.js';
import { As001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-001/as-001.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As001CfnAdapterFactory();

function runControl(properties: Record<string, unknown>) {
  const resource = { Type: 'AWS::AutoScaling::AutoScalingGroup', Properties: properties };
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context = {
    stackName: 'test-stack',
    template,
    resource: resource as unknown as CfnContext['resource'],
    logicalId: 'Asg',
  } as CfnContext;
  const adapter = factory.bind(context);
  return as001Control.run(adapter as never, context);
}

describe('AS-001 CloudFormation: Auto Scaling Group default cooldown', () => {
  // Primary behaviour owned by this requirement: omitting Cooldown yields the
  // service default of 300 seconds, which is nonzero, so the group passes.
  it('does not flag an ASG declared with capacity and launch settings but no Cooldown property', () => {
    const result = runControl({
      MinSize: '1',
      MaxSize: '3',
      DesiredCapacity: '2',
      LaunchTemplate: {
        LaunchTemplateId: 'MyLaunchTemplate',
        Version: '1',
      },
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).toBeNull();
  });

  it('does not flag an ASG that sets an explicit nonzero Cooldown', () => {
    const result = runControl({
      MinSize: '1',
      MaxSize: '3',
      DesiredCapacity: '2',
      LaunchTemplate: {
        LaunchTemplateId: 'MyLaunchTemplate',
        Version: '1',
      },
      AvailabilityZones: ['us-east-1a'],
      Cooldown: '300',
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is a Cooldown
  // that is present but zero, which is not a configured cooldown period.
  it('flags an ASG whose Cooldown is explicitly set to zero', () => {
    const result = runControl({
      MinSize: '1',
      MaxSize: '3',
      DesiredCapacity: '2',
      LaunchTemplate: {
        LaunchTemplateId: 'MyLaunchTemplate',
        Version: '1',
      },
      AvailabilityZones: ['us-east-1a'],
      Cooldown: '0',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-001');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
