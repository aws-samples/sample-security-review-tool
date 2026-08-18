import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { As005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function run(properties: Record<string, unknown>) {
  const resource = { Type: 'AWS::AutoScaling::AutoScalingGroup', Properties: properties } as unknown as Resource;
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
  const adapter = factory.bind(context) as As005Adapter;
  return as005Control.run(adapter, context);
}

const BASE_PROPERTIES = {
  MinSize: '1',
  MaxSize: '3',
  AvailabilityZones: ['us-east-1a'],
};

describe('AS-005 CloudFormation — mixed instances policy with launch template id and version, no overrides', () => {
  // REQ-04 owns this behavior: a mixed instances policy naming a launch template
  // (id + version) with no overrides means the group runs on a launch template.
  it('does not flag an Auto Scaling group whose mixed instances policy names a launch template by id and version', () => {
    const result = run({
      ...BASE_PROPERTIES,
      MixedInstancesPolicy: {
        LaunchTemplate: {
          LaunchTemplateSpecification: {
            LaunchTemplateId: 'lt-0123456789abcdef0',
            Version: '3',
          },
        },
      },
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the same group backed by a launch configuration instead of the
  // mixed instances policy must be flagged.
  it('flags an Auto Scaling group that names a launch configuration instead of a mixed instances policy', () => {
    const result = run({
      ...BASE_PROPERTIES,
      LaunchConfigurationName: 'my-launch-configuration',
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
