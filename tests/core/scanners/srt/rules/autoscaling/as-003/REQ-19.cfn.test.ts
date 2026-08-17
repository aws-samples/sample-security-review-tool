import { describe, expect, it } from 'vitest';
import { as003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.control.js';
import { As003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/as-003/as-003.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new As003CfnAdapterFactory();

/**
 * The destination topic comes from a deployment-time input (a cross-stack import),
 * which preprocessing leaves as an opaque object - the analysis cannot resolve it.
 */
const UNRESOLVED_TOPIC = { 'Fn::ImportValue': 'SharedScalingTopicArn' };

function groupWith(notificationTypes: string[]): Resource {
  return {
    Type: 'AWS::AutoScaling::AutoScalingGroup',
    Properties: {
      MinSize: '1',
      MaxSize: '3',
      AvailabilityZones: ['us-east-1a'],
      NotificationConfigurations: [
        {
          TopicARN: UNRESOLVED_TOPIC,
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

describe('AS-003 CloudFormation - notification configuration must deliver real scaling events', () => {
  // Primary behaviour owned by AS-003: only the test notification is covered, so no
  // launch, terminate, or failure event is ever delivered, whatever the topic resolves to.
  it('flags a group whose only notification type is autoscaling:TEST_NOTIFICATION with an unresolvable topic', () => {
    const result = scan(groupWith(['autoscaling:TEST_NOTIFICATION']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('AS-003');
    expect(result?.resourceName).toBe('Asg');
    expect(result?.resourceType).toBe('AWS::AutoScaling::AutoScalingGroup');
  });

  // Opposite outcome: identical fixture, unresolvable topic unchanged, but the event
  // type list now includes a real scaling event - nothing to flag.
  it('does not flag a group whose notification types include a real scaling event with the same unresolvable topic', () => {
    const result = scan(groupWith(['autoscaling:EC2_INSTANCE_LAUNCH', 'autoscaling:TEST_NOTIFICATION']));

    expect(result).toBeNull();
  });
});
