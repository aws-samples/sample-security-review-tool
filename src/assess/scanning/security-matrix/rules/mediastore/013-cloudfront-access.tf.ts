import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaStore013Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIASTORE-013', 'HIGH', 'MediaStore container must have resource policy to restrict CloudFront access', ['aws_media_store_container']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_media_store_container') {
      const containerPolicy = allResources.find(r =>
        r.type === 'aws_media_store_container_policy' &&
        r.values?.container_name === resource.values?.name
      );

      if (!containerPolicy) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_media_store_container_policy with a policy that restricts access to CloudFront via SourceArn condition.');
      }

      const policy = containerPolicy.values?.policy || '';
      const policyStr = typeof policy === 'string' ? policy : JSON.stringify(policy);
      if (!policyStr.includes('cloudfront') && !policyStr.includes('SourceArn')) {
        return this.createScanResult(resource, projectName, this.description, 'Add CloudFront service principal with SourceArn condition to the container policy.');
      }
    }

    return null;
  }
}

export default new TfMediaStore013Rule();
