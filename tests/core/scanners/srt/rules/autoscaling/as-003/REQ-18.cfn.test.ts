import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function contextFor(notificationConfigurations: unknown): CfnContext {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      NotificationConfigurations: notificationConfigurations,
    },
  } as unknown as Resource;
  const template = { Resources: { AppAsg: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: 'AppAsg' };
}

function run(notificationConfigurations: unknown) {
  const context = contextFor(notificationConfigurations);
  const adapter = factory.bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 CloudFormation - two notification configurations covering launch and terminate', () => {
  // Primary behavior owned by AS-003: launch/terminate/failure coverage via SNS satisfies the rule.
  it('passes when one configuration covers instance launch and another covers instance terminate, each with its own topic', () => {
    const result = run([
      {
        NotificationTypes: ['autoscaling:EC2_INSTANCE_LAUNCH'],
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-launch-events',
      },
      {
        NotificationTypes: ['autoscaling:EC2_INSTANCE_TERMINATE'],
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-terminate-events',
      },
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: same two-configuration shape, same topics, but neither delivers a real scaling event.
  it('flags when both configurations cover only the test notification instead of launch or terminate events', () => {
    const result = run([
      {
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-launch-events',
      },
      {
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-terminate-events',
      },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('AppAsg');
  });
});
