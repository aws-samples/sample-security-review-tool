import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (AS-005): An Auto Scaling group whose launch configuration name comes entirely from a
 * deploy-time input, with no launch template and no mixed instances policy, must be flagged —
 * every possible value of that input yields a launch-configuration-backed group.
 *
 * Fixtures are written post-`parseCfnTemplate`: `!Ref LaunchConfigName` for a parameter with no
 * default resolves to the string "DEFAULT".
 */

const factory = new As005CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = {
    Parameters: { LaunchConfigName: { Type: 'String' } },
    Resources: { Asg: resource },
  } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function issueFor(key: 'LAUNCH_CONFIGURATION_ONLY'): string {
  const finding = as005Control.findings[key];
  return typeof finding.issue === 'function' ? finding.issue({ resourceId: 'Asg', resourceType: 'AWS::AutoScaling::AutoScalingGroup' } as never) : finding.issue;
}

describe('AS-005 CloudFormation - deploy-time launch configuration name', () => {
  it('flags a group whose only instance source is a launch configuration name from a deploy-time parameter', () => {
    const context = buildContext({
      MinSize: '1',
      MaxSize: '2',
      // !Ref LaunchConfigName, parameter without a default
      LaunchConfigurationName: 'DEFAULT',
    });

    const result = as005Control.run(factory.bind(context), context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.issue).toBe(issueFor('LAUNCH_CONFIGURATION_ONLY'));
  });

  // Opposite outcome: identical group, except a launch template now backs it, so the rule passes.
  it('does not flag the same group when it also references a launch template', () => {
    const context = buildContext({
      MinSize: '1',
      MaxSize: '2',
      LaunchConfigurationName: 'DEFAULT',
      LaunchTemplate: { LaunchTemplateId: 'MyLaunchTemplate', Version: '1' },
    });

    const result = as005Control.run(factory.bind(context), context);

    expect(result).toBeNull();
  });
});
