import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

function buildGroup(notificationTypes: unknown): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      NotificationConfigurations: [
        {
          TopicARN: 'arn:aws:sns:us-east-1:123456789012:scaling-events',
          NotificationTypes: notificationTypes,
        },
      ],
    },
  } as unknown as Resource;
}

function scan(resource: Resource): ScanResult | null {
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  return as003Control.run(factory.bind(context), context);
}

describe('AS-003 REQ-08 (CloudFormation): notification event type must be a recognized Auto Scaling event type', () => {
  it('flags an Auto Scaling group whose notification event type is not a recognized Auto Scaling event type', () => {
    const result = scan(buildGroup(['autoscaling:EC2_INSTANCE_REBOOT']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
  });

  it('flags a group whose only notification event types are all unrecognized strings', () => {
    const result = scan(buildGroup(['EC2_INSTANCE_LAUNCH', 'autoscaling:SCALING_ACTIVITY']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });

  // Opposite outcome: the nearest input that flips the verdict is the same
  // configuration with a recognized event type. Primary behavior for the
  // "recognized event type is present" case is owned by the base AS-003
  // requirement; asserted here only to prove this file discriminates.
  it('does not flag an Auto Scaling group whose notification event type is a recognized Auto Scaling event type', () => {
    const result = scan(buildGroup(['autoscaling:EC2_INSTANCE_LAUNCH']));

    expect(result).toBeNull();
  });

  it('does not flag when an unrecognized event type sits alongside a recognized one', () => {
    const result = scan(buildGroup(['autoscaling:EC2_INSTANCE_REBOOT', 'autoscaling:EC2_INSTANCE_TERMINATE_ERROR']));

    expect(result).toBeNull();
  });
});
