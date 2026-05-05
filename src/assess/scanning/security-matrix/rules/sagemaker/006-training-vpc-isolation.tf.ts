import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker006Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-006', 'HIGH', 'SageMaker training job does not have VPC isolation configured', ['aws_sagemaker_notebook_instance']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      if (!resource.values?.subnet_id) {
        return this.createScanResult(resource, projectName, this.description, 'Configure subnet_id and security_groups to enable VPC isolation for training workloads.');
      }
    }

    return null;
  }
}

export default new TfSageMaker006Rule();
