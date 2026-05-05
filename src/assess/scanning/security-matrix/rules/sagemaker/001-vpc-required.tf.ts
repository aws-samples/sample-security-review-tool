import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker001Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-001', 'HIGH', 'SageMaker resource is not configured to use a VPC', ['aws_sagemaker_notebook_instance', 'aws_sagemaker_domain']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      if (!resource.values?.subnet_id) {
        return this.createScanResult(resource, projectName, this.description, 'Set subnet_id to provision the notebook instance in a VPC subnet.');
      }
    }

    if (resource.type === 'aws_sagemaker_domain') {
      if (!resource.values?.subnet_ids || resource.values.subnet_ids.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Set subnet_ids to provision the SageMaker domain in a VPC.');
      }
    }

    return null;
  }
}

export default new TfSageMaker001Rule();
