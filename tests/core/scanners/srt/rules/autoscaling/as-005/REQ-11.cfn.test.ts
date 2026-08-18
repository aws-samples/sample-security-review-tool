import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '2',
      AvailabilityZones: ['us-east-1a'],
      ...properties,
    },
  } as unknown as Resource;

  const template = { Resources: { AsgResource: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'AsgResource' };
}

function run(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  return as005Control.run(factory.bind(context), context);
}

describe('AS-005 CloudFormation - launch template identifier only known at deployment time (REQ-11)', () => {
  it('passes when LaunchTemplateId comes from an unresolved cross-stack import', () => {
    const result = run({
      LaunchTemplate: {
        LaunchTemplateId: { 'Fn::ImportValue': 'SharedLaunchTemplateId' },
        Version: '1',
      },
    });

    expect(result).toBeNull();
  });

  it('passes when LaunchTemplateName comes from an unresolved conditional value', () => {
    const result = run({
      LaunchTemplate: {
        LaunchTemplateName: { 'Fn::If': ['UseBlue', 'blue-template', 'green-template'] },
        Version: '1',
      },
    });

    expect(result).toBeNull();
  });

  it('passes when the whole LaunchTemplate reference is an unresolved intrinsic', () => {
    const result = run({
      LaunchTemplate: { 'Fn::If': ['UseBlue', { LaunchTemplateName: 'blue' }, { LaunchTemplateName: 'green' }] },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the primary behaviour (flagging a launch configuration) is owned by
  // the base requirement of AS-005. Same deployment-time-unknown identifier, but supplied as a
  // launch configuration instead of a launch template, which must be flagged.
  it('flags the group when the deployment-time value names a launch configuration instead', () => {
    const result = run({
      LaunchConfigurationName: { 'Fn::ImportValue': 'SharedLaunchConfigurationName' },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('AsgResource');
    expect(result?.issue).toContain('launch configuration');
  });
});
