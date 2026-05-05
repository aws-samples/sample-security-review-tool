import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElasticBeanstalk003Rule extends BaseTerraformRule {
  constructor() {
    super('EB-003', 'HIGH', 'Elastic Beanstalk environment does not have platform updates enabled', ['aws_elastic_beanstalk_environment']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elastic_beanstalk_environment') {
      const settings = resource.values?.setting;
      if (!Array.isArray(settings)) {
        return this.createScanResult(resource, projectName, this.description, 'Add setting with namespace "aws:elasticbeanstalk:managedactions" and name "ManagedActionsEnabled" value "true".');
      }

      const managedActions = settings.find((s: any) =>
        s.namespace === 'aws:elasticbeanstalk:managedactions' &&
        s.name === 'ManagedActionsEnabled'
      );

      if (!managedActions || managedActions.value !== 'true') {
        return this.createScanResult(resource, projectName, this.description, 'Set ManagedActionsEnabled to "true" in aws:elasticbeanstalk:managedactions namespace.');
      }
    }

    return null;
  }
}

export default new TfElasticBeanstalk003Rule();
