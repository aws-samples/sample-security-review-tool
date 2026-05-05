import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker009Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-009', 'HIGH', 'SageMaker notebook instance has root access enabled', ['aws_sagemaker_notebook_instance']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_notebook_instance') {
      const rootAccess = resource.values?.root_access;
      if (rootAccess !== 'Disabled') {
        return this.createScanResult(resource, projectName, this.description, 'Set root_access = "Disabled" to prevent root access on notebook instances.');
      }
    }

    return null;
  }
}

export default new TfSageMaker009Rule();
