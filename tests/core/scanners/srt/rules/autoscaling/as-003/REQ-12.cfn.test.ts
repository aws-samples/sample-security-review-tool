import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * AS-003 - Auto Scaling Groups must have notification configurations for launch,
 * terminate, or failure events.
 *
 * REQ-12 (primary behavior owned by this file): when whether the Auto Scaling group
 * ends up with a notification configuration at all is decided by a deployment-time
 * condition that analysis cannot resolve, the scanner cannot assert a breach - one of
 * the two possible outcomes complies - so the control must PASS (return null).
 *
 * Fixtures below are written in post-preprocessing form: `Fn::If` is NOT resolved by
 * `parseCfnTemplate`, so the rule really does see the raw `{ "Fn::If": [...] }` object.
 */

const factory = new As003CfnAdapterFactory();

function runControl(properties: Record<string, unknown>): ScanResult | null {
  const resource = {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: properties,
  } as unknown as Resource;
  const template = { Resources: { Asg: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Asg',
  };
  const adapter: As003Adapter = factory.bind(context);
  return as003Control.run(adapter, context);
}

const BASE_PROPERTIES = {
  MinSize: '1',
  MaxSize: '3',
  AvailabilityZones: ['us-east-1a'],
};

describe('AS-003 CloudFormation - notification configuration gated by an unresolvable condition', () => {
  it('passes when the entire NotificationConfigurations value is an unresolved Fn::If', () => {
    const result = runControl({
      ...BASE_PROPERTIES,
      NotificationConfigurations: {
        'Fn::If': [
          'EnableNotifications',
          [
            {
              TopicARN: 'NotificationTopic',
              NotificationTypes: ['autoscaling:EC2_INSTANCE_LAUNCH', 'autoscaling:EC2_INSTANCE_TERMINATE'],
            },
          ],
          { Ref: 'AWS::NoValue' },
        ],
      },
    });

    expect(result).toBeNull();
  });

  it('passes when a single notification configuration entry is an unresolved Fn::If', () => {
    const result = runControl({
      ...BASE_PROPERTIES,
      NotificationConfigurations: {
        'Fn::If': [
          'EnableNotifications',
          [
            {
              TopicARN: { 'Fn::ImportValue': 'SharedNotificationTopicArn' },
              NotificationTypes: ['autoscaling:EC2_INSTANCE_LAUNCH_ERROR'],
            },
          ],
          [],
        ],
      },
    });

    expect(result).toBeNull();
  });

  /**
   * Opposite outcome. The nearest input that flips the verdict: the condition is gone,
   * so the notification configuration is fully known - and known to cover only the test
   * notification, which delivers no real scaling event. Primary behavior for this case is
   * owned by the test-notification-only requirement; it appears here purely to prove this
   * file can distinguish "unknown" from "known and non-compliant".
   */
  it('reports a finding when the resolved notification configuration covers only the test notification', () => {
    const result = runControl({
      ...BASE_PROPERTIES,
      NotificationConfigurations: [
        {
          TopicARN: 'NotificationTopic',
          NotificationTypes: ['autoscaling:TEST_NOTIFICATION'],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });
});
