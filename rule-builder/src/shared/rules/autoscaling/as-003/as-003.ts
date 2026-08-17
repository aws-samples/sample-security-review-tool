import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'FixtureVpc', {
      maxAzs: 2,
      natGateways: 0,
    });

    const launchTemplate = new ec2.CfnLaunchTemplate(this, 'FixtureLaunchTemplate', {
      launchTemplateData: {
        instanceType: 't3.micro',
        imageId: 'ami-0000000000000000',
      },
    });

    const availabilityZones = [this.availabilityZones[0]];

    // Scenario: missing-notification-configuration
    // No NotificationConfigurations property at all - no notifications are configured.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgMissingNotificationConfig', {
      minSize: '1',
      maxSize: '1',
      availabilityZones,
      launchTemplate: {
        launchTemplateId: launchTemplate.ref,
        version: launchTemplate.attrLatestVersionNumber,
      },
    });

    // Scenario: test-notification-only
    // Notification configuration exists but only covers the TEST_NOTIFICATION event type.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgTestNotificationOnly', {
      minSize: '1',
      maxSize: '1',
      availabilityZones,
      launchTemplate: {
        launchTemplateId: launchTemplate.ref,
        version: launchTemplate.attrLatestVersionNumber,
      },
      notificationConfigurations: [
        {
          topicArn: 'arn:aws:sns:us-east-1:123456789012:fixture-topic',
          notificationTypes: ['autoscaling:TEST_NOTIFICATION'],
        },
      ],
    });

    // Scenario: empty-event-type-list
    // Notification configuration names a real topic but lists no event types.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgEmptyEventTypeList', {
      minSize: '1',
      maxSize: '1',
      availabilityZones,
      launchTemplate: {
        launchTemplateId: launchTemplate.ref,
        version: launchTemplate.attrLatestVersionNumber,
      },
      notificationConfigurations: [
        {
          topicArn: 'arn:aws:sns:us-east-1:123456789012:fixture-topic',
          notificationTypes: [],
        },
      ],
    });

    // Scenario: unrecognized-event-type
    // Notification configuration names a real topic but lists only an event type Auto Scaling does not recognize.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgUnrecognizedEventType', {
      minSize: '1',
      maxSize: '1',
      availabilityZones,
      launchTemplate: {
        launchTemplateId: launchTemplate.ref,
        version: launchTemplate.attrLatestVersionNumber,
      },
      notificationConfigurations: [
        {
          topicArn: 'arn:aws:sns:us-east-1:123456789012:fixture-topic',
          notificationTypes: ['autoscaling:BOGUS_EVENT_TYPE'],
        },
      ],
    });

    // Scenario: empty-destination-topic
    // Notification configuration lists real event types but names an empty destination topic.
    new autoscaling.CfnAutoScalingGroup(this, 'AsgEmptyDestinationTopic', {
      minSize: '1',
      maxSize: '1',
      availabilityZones,
      launchTemplate: {
        launchTemplateId: launchTemplate.ref,
        version: launchTemplate.attrLatestVersionNumber,
      },
      notificationConfigurations: [
        {
          topicArn: '',
          notificationTypes: [
            'autoscaling:EC2_INSTANCE_LAUNCH',
            'autoscaling:EC2_INSTANCE_LAUNCH_ERROR',
            'autoscaling:EC2_INSTANCE_TERMINATE',
            'autoscaling:EC2_INSTANCE_TERMINATE_ERROR',
          ],
        },
      ],
    });
  }
}
