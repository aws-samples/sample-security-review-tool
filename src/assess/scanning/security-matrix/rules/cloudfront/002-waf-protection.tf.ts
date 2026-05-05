import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCfr002Rule extends BaseTerraformRule {
  constructor() {
    super('CFR-002', 'HIGH', 'CloudFront distribution lacks WAF protection', ['aws_cloudfront_distribution']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_cloudfront_distribution') {
      const webAclId = resource.values?.web_acl_id;
      if (!webAclId) {
        return this.createScanResult(resource, projectName, this.description, 'Set web_acl_id to associate a WAFv2 Web ACL with this CloudFront distribution.');
      }
    }

    return null;
  }
}

export default new TfCfr002Rule();
