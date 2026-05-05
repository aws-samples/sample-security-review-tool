import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker005Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-005', 'HIGH', 'SageMaker resource does not have security groups configured', ['aws_sagemaker_notebook_instance', 'aws_sagemaker_domain']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      const securityGroups = resource.values?.security_groups;
      if (!securityGroups || securityGroups.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Set security_groups to restrict network access to the notebook instance.');
      }
    }

    if (resource.type === 'aws_sagemaker_domain') {
      const securityGroups = resource.values?.default_user_settings?.security_groups;
      if (!securityGroups || securityGroups.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Set default_user_settings.security_groups to restrict network access.');
      }
    }

    return null;
  }
}

export default new TfSageMaker005Rule();
