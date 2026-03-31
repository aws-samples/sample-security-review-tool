import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EB3 Rule: Are platform updates enabled for the application environment?
 * 
 * Documentation: "Solutions should have platform updates enabled for beanstalk environments in order to receive 
 * bug fixes, software updates and new features. Managed platform updates perform immutable environment updates."
 */
export class ElasticBeanstalk003Rule extends BaseRule {
  constructor() {
    super(
      'EB-003',
      'HIGH',
      'Elastic Beanstalk environment does not have platform updates enabled',
      ['AWS::ElasticBeanstalk::Environment']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ElasticBeanstalk::Environment') {
      return null;
    }

    const optionSettings = resource.Properties?.OptionSettings || [];
    
    // Check for managed platform updates configuration
    const updateLevel = optionSettings.find((setting: any) => 
      setting.Namespace === 'aws:elasticbeanstalk:managedactions' && 
      setting.OptionName === 'ManagedActionsEnabled'
    );

    const platformUpdateLevel = optionSettings.find((setting: any) => 
      setting.Namespace === 'aws:elasticbeanstalk:managedactions:platformupdate' && 
      setting.OptionName === 'UpdateLevel'
    );

    if (!updateLevel || updateLevel.Value !== 'true') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable managed actions by adding OptionSetting with Namespace 'aws:elasticbeanstalk:managedactions', OptionName 'ManagedActionsEnabled', and Value 'true'.`
      );
    }

    if (!platformUpdateLevel || platformUpdateLevel.Value !== 'minor') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable platform updates by adding OptionSetting with Namespace 'aws:elasticbeanstalk:managedactions:platformupdate', OptionName 'UpdateLevel', and Value 'minor'.`
      );
    }

    return null;
  }
}

export default new ElasticBeanstalk003Rule();