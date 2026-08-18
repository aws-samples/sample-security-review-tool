import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'InstanceBasedGroup';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As005CfnAdapterFactory().bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

describe('AS-005 CloudFormation: Auto Scaling group built from an existing EC2 instance id', () => {
  // Primary behavior owned by AS-005: an ASG based on InstanceId gets an
  // Amazon EC2 Auto Scaling generated launch configuration, not a launch template.
  it('flags an Auto Scaling group whose only instance configuration source is an existing instance id', () => {
    const result = run({
      InstanceId: 'i-0123456789abcdef0',
      MinSize: '1',
      MaxSize: '2',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: same group, but the instance settings come from a launch template.
  it('does not flag the same Auto Scaling group when it references a launch template instead', () => {
    const result = run({
      LaunchTemplate: { LaunchTemplateId: 'MyLaunchTemplate', Version: '1' },
      MinSize: '1',
      MaxSize: '2',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).toBeNull();
  });
});
