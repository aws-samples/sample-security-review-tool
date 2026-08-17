import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.tf.js';
import type { As003Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * AS-003 - Auto Scaling Groups must have notification configurations for launch,
 * terminate, or failure events.
 *
 * REQ-12 (primary behavior owned by this file): when whether a notification
 * configuration covers the Auto Scaling group is decided by a deployment-time
 * condition the reader cannot resolve, the scanner cannot assert a breach - one of the
 * two possible outcomes complies - so the control must PASS (return null).
 *
 * In Terraform source that gate is written as a conditional expression, which the
 * reader hands over marked `__unresolved__:`.
 */

const factory = new As003TfAdapterFactory();

function unresolved(expression: string): string {
  return `__unresolved__:${expression}`;
}

const group: TerraformResource = {
  type: 'aws_autoscaling_group',
  name: 'app',
  address: 'aws_autoscaling_group.app',
  values: {
    name: 'app-asg',
    min_size: 1,
    max_size: 3,
  },
} as unknown as TerraformResource;

function runControl(notification: TerraformResource): ScanResult | null {
  const allResources = [group, notification];
  const context: TfContext = {
    projectName: 'test-project',
    resource: group,
    allResources,
  };
  const adapter: As003Adapter = factory.bind(context);
  return as003Control.run(adapter, context);
}

describe('AS-003 Terraform - notification coverage gated by an unresolvable condition', () => {
  it('passes when the notification group_names list is an unresolved conditional expression', () => {
    const notification = {
      type: 'aws_autoscaling_notification',
      name: 'scaling',
      address: 'aws_autoscaling_notification.scaling',
      values: {
        group_names: unresolved('var.enable_notifications ? [aws_autoscaling_group.app.name] : []'),
        notifications: ['autoscaling:EC2_INSTANCE_LAUNCH', 'autoscaling:EC2_INSTANCE_TERMINATE'],
        topic_arn: 'aws_sns_topic.scaling',
      },
    } as unknown as TerraformResource;

    expect(runControl(notification)).toBeNull();
  });

  it('passes when the group name inside group_names is an unresolved conditional expression', () => {
    const notification = {
      type: 'aws_autoscaling_notification',
      name: 'scaling',
      address: 'aws_autoscaling_notification.scaling',
      values: {
        group_names: [unresolved('var.enable_notifications ? aws_autoscaling_group.app.name : ""')],
        notifications: ['autoscaling:EC2_INSTANCE_LAUNCH_ERROR'],
        topic_arn: 'aws_sns_topic.scaling',
      },
    } as unknown as TerraformResource;

    expect(runControl(notification)).toBeNull();
  });

  /**
   * Opposite outcome. The nearest input that flips the verdict: the conditional is gone,
   * so coverage of this group is fully known - and the covering notification is known to
   * deliver only the test notification, never a real scaling event. Primary behavior for
   * that case is owned by the test-notification-only requirement; it appears here purely
   * to prove this file can distinguish "unknown" from "known and non-compliant".
   */
  it('reports a finding when coverage is resolved and the notification lists only the test notification', () => {
    const notification = {
      type: 'aws_autoscaling_notification',
      name: 'scaling',
      address: 'aws_autoscaling_notification.scaling',
      values: {
        group_names: ['aws_autoscaling_group.app'],
        notifications: ['autoscaling:TEST_NOTIFICATION'],
        topic_arn: 'aws_sns_topic.scaling',
      },
    } as unknown as TerraformResource;

    const result = runControl(notification);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
  });
});
