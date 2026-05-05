import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * AUTOSCALING-001 Rule: Implement IAM roles in Amazon EC2 launch templates.
 * 
 * Documentation: "AWS recommends using launch templates in Auto Scaling because it allows granular permissions."
 */
export class AUTOSCALING001Rule extends BaseRule {
  constructor() {
    super(
      'AUTOSCALING-001',
      'HIGH',
      'Auto Scaling Group does not use launch template with IAM role configuration',
      ['AWS::AutoScaling::AutoScalingGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
      return null;
    }

    return this.evaluateAutoScalingGroup(resource, stackName);
  }

  private evaluateAutoScalingGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const launchTemplate = resource.Properties?.LaunchTemplate;
    const mixedInstancesPolicy = resource.Properties?.MixedInstancesPolicy;

    // Flag if no launch template specified
    if (!launchTemplate && !mixedInstancesPolicy) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add LaunchTemplate property for granular IAM permissions.`
      );
    }

    // Flag if launch template exists but has no identifier
    if (launchTemplate && !launchTemplate.LaunchTemplateId && !launchTemplate.LaunchTemplateName) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add LaunchTemplateId or LaunchTemplateName to LaunchTemplate property.`
      );
    }

    return null;
  }
}

export default new AUTOSCALING001Rule();