import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaStore014Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIASTORE-014', 'HIGH', 'MediaStore container must implement deny-by-default policy to prevent unintended access', ['aws_media_store_container']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_media_store_container') {
      const containerPolicy = allResources.find(r =>
        r.type === 'aws_media_store_container_policy' &&
        r.values?.container_name === resource.values?.name
      );

      if (!containerPolicy) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_media_store_container_policy with a Deny statement for aws:SecureTransport = false.');
      }

      const policy = containerPolicy.values?.policy || '';
      const policyStr = typeof policy === 'string' ? policy : JSON.stringify(policy);

      if (!policyStr.includes('Deny') || !policyStr.includes('SecureTransport')) {
        return this.createScanResult(resource, projectName, this.description, 'Add deny statement for non-HTTPS access: Deny when aws:SecureTransport is false.');
      }
    }

    return null;
  }
}

export default new TfMediaStore014Rule();
