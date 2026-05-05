import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker010Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-010', 'MEDIUM', 'SageMaker resources share IAM roles instead of using dedicated roles', ['aws_sagemaker_notebook_instance']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      const roleArn = resource.values?.role_arn;
      if (!roleArn) return null;

      const otherInstances = allResources.filter(r =>
        r.type === 'aws_sagemaker_notebook_instance' &&
        r.address !== resource.address &&
        r.values?.role_arn === roleArn
      );

      if (otherInstances.length > 0) {
        return this.createScanResult(resource, projectName, this.description, 'Use a dedicated IAM role for each SageMaker notebook instance.');
      }
    }

    return null;
  }
}

export default new TfSageMaker010Rule();
