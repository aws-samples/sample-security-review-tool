import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElasticBeanstalk002Rule extends BaseTerraformRule {
  constructor() {
    super('EB-002', 'HIGH', 'Elastic Beanstalk environment does not have IAM instance profile configured', ['aws_elastic_beanstalk_environment']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elastic_beanstalk_environment') {
      const settings = resource.values?.setting;
      if (!Array.isArray(settings)) {
        return this.createScanResult(resource, projectName, this.description, 'Add setting with namespace "aws:autoscaling:launchconfiguration" and name "IamInstanceProfile".');
      }

      const hasInstanceProfile = settings.some((s: any) =>
        s.namespace === 'aws:autoscaling:launchconfiguration' &&
        s.name === 'IamInstanceProfile'
      );

      if (!hasInstanceProfile) {
        return this.createScanResult(resource, projectName, this.description, 'Add setting with namespace "aws:autoscaling:launchconfiguration" and name "IamInstanceProfile".');
      }
    }

    return null;
  }
}

export default new TfElasticBeanstalk002Rule();
