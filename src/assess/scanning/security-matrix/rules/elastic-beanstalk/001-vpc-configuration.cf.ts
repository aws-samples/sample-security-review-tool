import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EB1 Rule: Is the beanstalk environment configured to use VPC?
 * 
 * Documentation: "The solution should use a VPC configured via ebextensions."
 */
export class ElasticBeanstalk001Rule extends BaseRule {
  constructor() {
    super(
      'EB-001',
      'HIGH',
      'Elastic Beanstalk environment is not configured with VPC',
      ['AWS::ElasticBeanstalk::Environment']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ElasticBeanstalk::Environment') {
      return null;
    }

    const optionSettings = resource.Properties?.OptionSettings || [];
    
    // Check for VPC configuration in option settings
    const hasVpcConfig = optionSettings.some((setting: any) => {
      // Direct VPC configuration
      if (setting.Namespace === 'aws:ec2:vpc' && 
          ['VPCId', 'Subnets', 'ELBSubnets', 'DBSubnets'].includes(setting.OptionName)) {
        return true;
      }
      
      // Security groups (implies VPC if not default VPC)
      if ((setting.Namespace === 'aws:autoscaling:launchconfiguration' && setting.OptionName === 'SecurityGroups') ||
          (setting.Namespace === 'aws:elb:loadbalancer' && setting.OptionName === 'SecurityGroups')) {
        return true;
      }
      
      return false;
    });

    if (!hasVpcConfig) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        `Add OptionSettings entry with Namespace 'aws:ec2:vpc' and OptionName 'VPCId' with Value referencing your VPC ID.`
      );
    }

    return null;
  }
}

export default new ElasticBeanstalk001Rule();