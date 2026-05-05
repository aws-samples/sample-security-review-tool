import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker003Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-003', 'HIGH', 'SageMaker notebook instance has direct internet access enabled', ['aws_sagemaker_notebook_instance']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      const directInternetAccess = resource.values?.direct_internet_access;
      if (directInternetAccess !== 'Disabled') {
        return this.createScanResult(resource, projectName, this.description, 'Set direct_internet_access = "Disabled" and use VPC endpoints for internet access.');
      }
    }

    return null;
  }
}

export default new TfSageMaker003Rule();
