import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSageMaker004Rule extends BaseTerraformRule {
  constructor() {
    super('SAGEMAKER-004', 'MEDIUM', 'SageMaker domain is not configured for Studio experience', ['aws_sagemaker_domain']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sagemaker_domain') {
      const appNetworkAccessType = resource.values?.app_network_access_type;
      if (appNetworkAccessType !== 'VpcOnly') {
        return this.createScanResult(resource, projectName, this.description, 'Set app_network_access_type = "VpcOnly" for secure Studio experience.');
      }
    }

    return null;
  }
}

export default new TfSageMaker004Rule();
