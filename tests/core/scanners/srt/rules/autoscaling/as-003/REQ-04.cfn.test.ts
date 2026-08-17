import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { Asg: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: 'Asg' };
}

function scan(resource: Resource) {
  const context = buildContext(resource);
  return as003Control.run(factory.bind(context), context);
}

function asg(notificationTypes: string[]): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '2',
      NotificationConfigurations: [
        {
          TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
          NotificationTypes: notificationTypes,
        },
      ],
    },
  } as unknown as Resource;
}

describe('AS-003 REQ-04 (CloudFormation): notification configuration listing only the test notification', () => {
  // Primary behavior owned by this requirement: a config whose only event type is
  // autoscaling:TEST_NOTIFICATION delivers no scaling event, so it must be flagged.
  it('flags an Auto Scaling group whose only notification type is autoscaling:TEST_NOTIFICATION', () => {
    const result = scan(asg(['autoscaling:TEST_NOTIFICATION']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
  });

  // Opposite outcome: only the event type changes to a real scaling event.
  it('does not flag an Auto Scaling group whose notification type is a real scaling event', () => {
    const result = scan(asg(['autoscaling:EC2_INSTANCE_LAUNCH']));

    expect(result).toBeNull();
  });

  it('does not flag when the test notification is listed alongside a real scaling event', () => {
    const result = scan(asg(['autoscaling:TEST_NOTIFICATION', 'autoscaling:EC2_INSTANCE_TERMINATE_ERROR']));

    expect(result).toBeNull();
  });
});
