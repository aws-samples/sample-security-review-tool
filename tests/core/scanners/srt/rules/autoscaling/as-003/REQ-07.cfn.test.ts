import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function scan(resource: Resource) {
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as003Control.run(factory.bind(context), context);
}

function group(notificationConfiguration: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '2',
      NotificationConfigurations: [notificationConfiguration],
    },
  } as unknown as Resource;
}

describe('AS-003 CloudFormation - notification configuration event types', () => {
  // Primary behavior for this requirement (REQ-07): a notification configuration
  // that supplies a destination topic but omits NotificationTypes entirely
  // subscribes to no scaling events at all, so it must be flagged.
  it('flags an Auto Scaling group whose notification configuration omits NotificationTypes while giving a topic', () => {
    const result = scan(group({
      TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
  });

  // Opposite outcome: same configuration, same topic, but the event type list is
  // present and names a real scaling event - nothing to flag.
  it('does not flag when the same notification configuration lists a real scaling event type', () => {
    const result = scan(group({
      TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
      NotificationTypes: [
        'autoscaling:EC2_INSTANCE_LAUNCH',
        'autoscaling:EC2_INSTANCE_TERMINATE',
        'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
      ],
    }));

    expect(result).toBeNull();
  });
});
