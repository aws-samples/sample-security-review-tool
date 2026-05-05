import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElasticBeanstalk001Rule extends BaseTerraformRule {
  constructor() {
    super('EB-001', 'HIGH', 'Elastic Beanstalk environment is not configured with VPC', ['aws_elastic_beanstalk_environment']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elastic_beanstalk_environment') {
      const settings = resource.values?.setting;
      if (!Array.isArray(settings)) {
        return this.createScanResult(resource, projectName, this.description, 'Add setting with namespace "aws:ec2:vpc" and name "VPCId".');
      }

      const hasVpcConfig = settings.some((s: any) =>
        s.namespace === 'aws:ec2:vpc' &&
        ['VPCId', 'Subnets', 'ELBSubnets'].includes(s.name)
      );

      if (!hasVpcConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Add setting with namespace "aws:ec2:vpc" and name "VPCId" with your VPC ID.');
      }
    }

    return null;
  }
}

export default new TfElasticBeanstalk001Rule();
