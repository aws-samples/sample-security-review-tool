import { describe, it, expect } from 'vitest';
import { as005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.control.js';
import { As005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-005/as-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As005CfnAdapterFactory();

function contextFor(properties: Record<string, unknown>): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;

  const template = { Resources: { Asg: resource } } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function run(properties: Record<string, unknown>) {
  const context = contextFor(properties);
  return as005Control.run(factory.bind(context), context);
}

describe('AS-005 (CloudFormation): launch template reference with an empty launch template id', () => {
  // Primary behavior owned by AS-005: an empty LaunchTemplateId is not a usable launch template.
  it('flags an Auto Scaling group whose direct launch template reference has an empty LaunchTemplateId and no launch configuration', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      LaunchTemplate: {
        LaunchTemplateId: '',
        Version: '1',
      },
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-005');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.resourceName).toBe('Asg');
  });

  it('does not flag the same group when the launch template id is a usable, non-empty value (opposite outcome)', () => {
    const result = run({
      MinSize: '1',
      MaxSize: '2',
      LaunchTemplate: {
        LaunchTemplateId: 'lt-0123456789abcdef0',
        Version: '1',
      },
    });

    expect(result).toBeNull();
  });
});
