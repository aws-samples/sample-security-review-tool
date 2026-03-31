import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * AS003 Rule: Configure email notifications for ASG scaling events.
 * 
 * Documentation: "Someone should own and act on autoscaling notifications. Periodically review ownership and SNS subscriber addresses."
 */
export class AS003Rule extends BaseRule {
  constructor() {
    super(
      'AS-003',
      'HIGH',
      'Auto Scaling Group does not have notification configurations',
      ['AWS::AutoScaling::AutoScalingGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
      return null;
    }

    const notificationConfigurations = resource.Properties?.NotificationConfigurations;

    if (!notificationConfigurations || !Array.isArray(notificationConfigurations) || notificationConfigurations.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add NotificationConfigurations property with TopicARN and NotificationTypes for scaling event notifications.`
      );
    }

    return null;
  }
}

export default new AS003Rule();