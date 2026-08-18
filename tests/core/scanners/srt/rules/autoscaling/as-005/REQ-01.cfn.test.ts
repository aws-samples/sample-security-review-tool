import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const RESOURCE_TYPE = 'AWS::AutoScaling::AutoScalingGroup';
const LOGICAL_ID = 'AppAsg';

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: RESOURCE_TYPE,
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Resources: {
      [LOGICAL_ID]: resource,
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = new As005CfnAdapterFactory().bind(context);
  return as005Control.run(adapter, context);
}

describe('AS-005 CloudFormation - Auto Scaling groups must use a launch template rather than a launch configuration', () => {
  // Primary behavior owned by this requirement: launch configuration only -> flag.
  it('flags an Auto Scaling group whose only instance configuration source is a launch configuration name', () => {
    const result = run({
      LaunchConfigurationName: 'legacy-app-launch-config',
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe(RESOURCE_TYPE);
  });

  // Opposite outcome: nearest input that flips the verdict - the same group wired to a
  // launch template instead of a launch configuration.
  it('does not flag an otherwise identical Auto Scaling group that references a launch template', () => {
    const result = run({
      LaunchTemplate: {
        LaunchTemplateId: 'AppLaunchTemplate',
        Version: '1',
      },
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
    });

    expect(result).toBeNull();
  });
});
