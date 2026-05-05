import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk004Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-004', 'HIGH', 'MSK cluster is not configured with IAM authentication', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const clientAuth = resource.values?.client_authentication;
      const iamEnabled = clientAuth?.sasl?.iam === true
        || clientAuth?.[0]?.sasl?.[0]?.iam === true;

      if (!iamEnabled) {
        return this.createScanResult(resource, projectName, this.description, 'Set client_authentication.sasl.iam = true to enable IAM authentication.');
      }
    }

    return null;
  }
}

export default new TfMsk004Rule();
