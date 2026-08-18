import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'Asg';
const factory = new As005CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function scan(properties: Record<string, unknown>): ScanResult | null {
  const context = buildContext(properties);
  return as005Control.run(factory.bind(context) as As005Adapter, context);
}

describe('AS-005 (CloudFormation): Auto Scaling groups must use a launch template', () => {
  // Primary behavior owned by AS-005: an empty LaunchConfigurationName leaves the group
  // with no launch-template-based instance configuration, so it must be flagged.
  it('flags a group whose LaunchConfigurationName is an empty string with no launch template and no mixed instances policy', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      LaunchConfigurationName: '',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: the nearest input that flips the verdict — the same group, still with an
  // empty LaunchConfigurationName, but now pointing at a launch template.
  it('does not flag the same group when a launch template reference is present alongside the empty LaunchConfigurationName', () => {
    const result = scan({
      MinSize: '1',
      MaxSize: '2',
      LaunchConfigurationName: '',
      LaunchTemplate: { LaunchTemplateId: 'lt-0123456789abcdef0', Version: '1' },
    });

    expect(result).toBeNull();
  });
});
