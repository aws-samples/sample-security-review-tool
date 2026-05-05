import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EB2 Rule: Is the solution using an IAM role for EC2 to eliminate the need to distribute and rotate long-term credentials?
 * 
 * Documentation: "The recommended approach for granting EC2-based applications AWS permissions is with an IAM role for EC2 
 * because this eliminates the need to distribute and rotate long-term credentials on EC2 instances."
 */
export class ElasticBeanstalk002Rule extends BaseRule {
  constructor() {
    super(
      'EB-002',
      'HIGH',
      'Elastic Beanstalk environment does not have IAM instance profile configured',
      ['AWS::ElasticBeanstalk::Environment']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ElasticBeanstalk::Environment') {
      return null;
    }

    const optionSettings = resource.Properties?.OptionSettings || [];
    
    // Check for IAM instance profile configuration
    const hasInstanceProfile = optionSettings.some((setting: any) => 
      setting.Namespace === 'aws:autoscaling:launchconfiguration' && 
      setting.OptionName === 'IamInstanceProfile'
    );

    if (!hasInstanceProfile) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add IAM instance profile to OptionSettings with Namespace 'aws:autoscaling:launchconfiguration' and OptionName 'IamInstanceProfile'.`
      );
    }

    return null;
  }
}

export default new ElasticBeanstalk002Rule();