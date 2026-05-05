import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk005Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-005', 'HIGH', 'MSK cluster does not have proper authentication configured for ACL authorization', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const clientAuth = resource.values?.client_authentication;
      const iamEnabled = clientAuth?.sasl?.iam === true
        || clientAuth?.[0]?.sasl?.[0]?.iam === true;
      const scramEnabled = clientAuth?.sasl?.scram === true
        || clientAuth?.[0]?.sasl?.[0]?.scram === true;

      if (!iamEnabled && !scramEnabled) {
        return this.createScanResult(resource, projectName, this.description, 'Set client_authentication.sasl.iam = true to enable IAM authentication for ACL authorization.');
      }
    }

    return null;
  }
}

export default new TfMsk005Rule();
