import { describe, expect, it } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function evaluate(resource: Resource, logicalId = 'AppAsg') {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  return as005Control.run(factory.bind(context) as As005Adapter, context);
}

describe('AS-005 CloudFormation - REQ-03: launch template by name plus version, no launch configuration', () => {
  // Primary behaviour owned by this requirement: a group whose instance configuration
  // comes from a launch template (name + version) and no launch configuration passes.
  it('returns no finding when the group references a launch template by name and version', () => {
    const result = evaluate({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '3',
        LaunchTemplate: {
          LaunchTemplateName: 'app-launch-template',
          Version: '3',
        },
      },
    } as unknown as Resource);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical group except the instance configuration source is a
  // launch configuration instead of a launch template.
  it('returns a finding when the group names a launch configuration instead of a launch template', () => {
    const result = evaluate({
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      Properties: {
        MinSize: '1',
        MaxSize: '3',
        LaunchConfigurationName: 'app-launch-config',
      },
    } as unknown as Resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('AppAsg');
  });
});
