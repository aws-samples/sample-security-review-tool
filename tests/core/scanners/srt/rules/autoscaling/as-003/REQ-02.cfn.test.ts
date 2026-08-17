import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { AsgWithNotifications: resource } } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'AsgWithNotifications',
  };
}

function run(resource: Resource) {
  const context = buildContext(resource);
  return as003Control.run(factory.bind(context), context);
}

function group(notificationConfigurations: unknown): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      // !Ref ScalingLaunchTemplate resolves to the logical id string
      LaunchTemplate: { LaunchTemplateId: 'ScalingLaunchTemplate', Version: '1' },
      AvailabilityZones: ['us-east-1a'],
      NotificationConfigurations: notificationConfigurations,
    },
  } as unknown as Resource;
}

describe('AS-003 REQ-02 (CloudFormation): notification configuration for scaling events', () => {
  // Primary behavior owned by AS-003: launch + terminate coverage satisfies the rule.
  it('passes when one notification configuration sends instance launch and terminate events to a topic', () => {
    const result = run(
      group([
        {
          // !Ref ScalingEventsTopic resolves to the logical id string
          TopicARN: 'ScalingEventsTopic',
          NotificationTypes: [
            'autoscaling:EC2_INSTANCE_LAUNCH',
            'autoscaling:EC2_INSTANCE_TERMINATE',
          ],
        },
      ]),
    );

    expect(result).toBeNull();
  });

  it('flags the group when the notification configuration list is present but carries no configuration', () => {
    const result = run(group([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('AsgWithNotifications');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });
});
