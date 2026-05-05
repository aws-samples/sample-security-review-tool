import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCfr006Rule extends BaseTerraformRule {
  constructor() {
    super('CFR-006', 'HIGH', 'CloudFront distribution does not use Origin Access Control for S3 origins', ['aws_cloudfront_distribution']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_cloudfront_distribution') {
      const origins = resource.values?.origin;
      if (Array.isArray(origins)) {
        for (const origin of origins) {
          const domainName = origin.domain_name || '';
          if (domainName.includes('.s3.') || domainName.includes('.s3-')) {
            const originAccessControlId = origin.origin_access_control_id;
            const s3OriginConfig = origin.s3_origin_config;
            if (!originAccessControlId && !s3OriginConfig?.origin_access_identity) {
              return this.createScanResult(resource, projectName, this.description, 'Set origin_access_control_id on S3 origins to use Origin Access Control (OAC) for secure access.');
            }
          }
        }
      }
    }

    return null;
  }
}

export default new TfCfr006Rule();
