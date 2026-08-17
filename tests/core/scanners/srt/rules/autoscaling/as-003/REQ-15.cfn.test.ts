import { describe, it, expect } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function contextFor(notificationConfigurations: unknown): CfnContext {
  const template = {
    Resources: {
      AppAsg: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          NotificationConfigurations: notificationConfigurations,
        },
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, any>)['AppAsg'],
    logicalId: 'AppAsg',
  };
}

function run(notificationConfigurations: unknown) {
  const context = contextFor(notificationConfigurations);
  return as003Control.run(factory.bind(context) as any, context);
}

describe('AS-003 (CloudFormation) - notification configurations deliver scaling events', () => {
  // Primary behavior owned by AS-003: a test-only configuration alongside a real
  // launch/terminate configuration does not remove scaling event coverage.
  it('passes when one configuration is test-only and another covers launch and terminate events', () => {
    const result = run([
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-test-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
      },
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-scaling-topic',
        NotificationTypes: [
          'autoscaling:EC2_INSTANCE_LAUNCH',
          'autoscaling:EC2_INSTANCE_TERMINATE',
        ],
      },
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: same two configurations, but the second one also covers only
  // the test notification, so no real scaling event is ever delivered.
  it('flags when both configurations cover only the test notification', () => {
    const result = run([
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-test-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
      },
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:asg-scaling-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
      },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('AppAsg');
  });
});
