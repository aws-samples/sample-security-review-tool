import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAutoScalingGroup';

function buildTemplate(notificationConfigurations: unknown[]): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          NotificationConfigurations: notificationConfigurations,
        },
      },
      LaunchAlarmTopic: { Type: 'AWS::SNS::Topic', Properties: {} },
      OpsAlarmTopic: { Type: 'AWS::SNS::Topic', Properties: {} },
    },
  } as unknown as Template;
}

function run(notificationConfigurations: unknown[]) {
  const template = buildTemplate(notificationConfigurations);
  const resource = (template.Resources as Record<string, Resource>)[LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'as-003-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new As003CfnAdapterFactory().bind(context);
  return as003Control.run(adapter, context);
}

describe('AS-003 CloudFormation - notification configurations limited to the test notification', () => {
  // Primary behavior owned by AS-003: only the four real scaling events count as coverage.
  it('flags an Auto Scaling group whose two notification configurations both cover only autoscaling:TEST_NOTIFICATION', () => {
    const result = run([
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:launch-alarm-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
      },
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:ops-alarm-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
      },
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
    expect(result?.issue).toMatch(/test notification/i);
  });

  // Opposite outcome: same two configurations, but one also covers a real scaling event.
  it('does not flag when one of the two configurations also covers a real launch event', () => {
    const result = run([
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:launch-alarm-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION', 'autoscaling:EC2_INSTANCE_LAUNCH'],
      },
      {
        TopicARN: 'arn:aws:sns:us-east-1:123456789012:ops-alarm-topic',
        NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
      },
    ]);

    expect(result).toBeNull();
  });
});
