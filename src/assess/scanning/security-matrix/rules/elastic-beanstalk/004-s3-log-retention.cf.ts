import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EB4 Rule: Is the solution configured for environment logs being retained and uploaded to Amazon S3?
 * 
 * Documentation: "Beanstalk environment logs should be retained and uploaded to Amazon S3 in order to keep 
 * the logging data for future audits, historical purposes or to track and analyze the EB application 
 * environment behavior for a long period of time."
 */
export class ElasticBeanstalk004Rule extends BaseRule {
  constructor() {
    super(
      'EB-004',
      'HIGH',
      'Elastic Beanstalk environment does not have S3 log retention configured',
      ['AWS::ElasticBeanstalk::Environment']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ElasticBeanstalk::Environment') {
      return null;
    }

    const optionSettings = resource.Properties?.OptionSettings || [];
    
    // Check for log streaming to S3 configuration
    const streamLogs = optionSettings.find((setting: any) => 
      setting.Namespace === 'aws:elasticbeanstalk:cloudwatch:logs' && 
      setting.OptionName === 'StreamLogs'
    );

    const retentionInDays = optionSettings.find((setting: any) => 
      setting.Namespace === 'aws:elasticbeanstalk:cloudwatch:logs' && 
      setting.OptionName === 'RetentionInDays'
    );

    if (!streamLogs || streamLogs.Value !== 'true') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable log streaming by adding OptionSetting with Namespace 'aws:elasticbeanstalk:cloudwatch:logs', OptionName 'StreamLogs', and Value 'true'.`
      );
    }

    if (!retentionInDays || !retentionInDays.Value) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure log retention by adding OptionSetting with Namespace 'aws:elasticbeanstalk:cloudwatch:logs', OptionName 'RetentionInDays', and Value '90'.`
      );
    }

    return null;
  }
}

export default new ElasticBeanstalk004Rule();