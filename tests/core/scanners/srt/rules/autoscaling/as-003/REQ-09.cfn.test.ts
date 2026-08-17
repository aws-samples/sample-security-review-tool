import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'AppAsg';
const TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:scaling-events';

const ALL_EVENT_TYPES = [
  'autoscaling:EC2_INSTANCE_LAUNCH',
  'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
  'autoscaling:EC2_INSTANCE_TERMINATE',
  'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
  'autoscaling:TEST_NOTIFICATION',
];

function buildTemplate(notificationTypes: string[]): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::AutoScaling::AutoScalingGroup',
        Properties: {
          MinSize: '1',
          MaxSize: '3',
          AvailabilityZones: ['us-east-1a'],
          NotificationConfigurations: [
            {
              TopicARN: TOPIC_ARN,
              NotificationTypes: notificationTypes,
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template): ScanResult | null {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, never>)[LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
  const adapter = new As003CfnAdapterFactory().bind(context) as As003Adapter;
  return as003Control.run(adapter, context);
}

describe('AS-003 CloudFormation - notification configuration covering all supported event types', () => {
  // Primary behaviour owned by this requirement: a notification configuration that
  // subscribes to every supported event type satisfies AS-003.
  it('passes when the notification configuration subscribes to all five supported event types', () => {
    expect(runControl(buildTemplate(ALL_EVENT_TYPES))).toBeNull();
  });

  // Opposite outcome: the notification configuration is still present with an SNS topic,
  // but the only event type is the test notification, so no real scaling event is delivered.
  it('flags when the same notification configuration covers only the test notification', () => {
    const result = runControl(buildTemplate(['autoscaling:TEST_NOTIFICATION']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });
});
