import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker008Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-008', 'HIGH', 'SageMaker notebook instance does not have data access restrictions configured', ['aws_sagemaker_notebook_instance']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      const roleArn = resource.values?.role_arn;
      if (!roleArn) {
        return this.createScanResult(resource, projectName, this.description, 'Set role_arn with a least-privilege IAM role to restrict data access.');
      }
    }

    return null;
  }
}

export default new TfSageMaker008Rule();
