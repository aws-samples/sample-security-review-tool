import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElasticBeanstalk004Rule extends BaseTerraformRule {
  constructor() {
    super('EB-004', 'HIGH', 'Elastic Beanstalk environment does not have S3 log retention configured', ['aws_elastic_beanstalk_environment']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elastic_beanstalk_environment') {
      const settings = resource.values?.setting;
      if (!Array.isArray(settings)) {
        return this.createScanResult(resource, projectName, this.description, 'Add setting with namespace "aws:elasticbeanstalk:cloudwatch:logs" and name "StreamLogs" value "true".');
      }

      const streamLogs = settings.find((s: any) =>
        s.namespace === 'aws:elasticbeanstalk:cloudwatch:logs' &&
        s.name === 'StreamLogs'
      );

      if (!streamLogs || streamLogs.value !== 'true') {
        return this.createScanResult(resource, projectName, this.description, 'Set StreamLogs to "true" in aws:elasticbeanstalk:cloudwatch:logs namespace.');
      }

      const retention = settings.find((s: any) =>
        s.namespace === 'aws:elasticbeanstalk:cloudwatch:logs' &&
        s.name === 'RetentionInDays'
      );

      if (!retention || !retention.value) {
        return this.createScanResult(resource, projectName, this.description, 'Set RetentionInDays in aws:elasticbeanstalk:cloudwatch:logs namespace.');
      }
    }

    return null;
  }
}

export default new TfElasticBeanstalk004Rule();
