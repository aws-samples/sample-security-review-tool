import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCfr005Rule extends BaseTerraformRule {
  constructor() {
    super('CFR-005', 'HIGH', 'CloudFront distribution does not enforce HTTPS for origin communication', ['aws_cloudfront_distribution']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_cloudfront_distribution') {
      const origins = resource.values?.origin;
      if (Array.isArray(origins)) {
        for (const origin of origins) {
          const customOriginConfig = origin.custom_origin_config;
          if (customOriginConfig) {
            const originProtocolPolicy = customOriginConfig.origin_protocol_policy;
            if (originProtocolPolicy === 'http-only' || originProtocolPolicy === 'match-viewer') {
              return this.createScanResult(resource, projectName, this.description, 'Set origin_protocol_policy to "https-only" in custom_origin_config for all origins.');
            }
          }
        }
      }
    }

    return null;
  }
}

export default new TfCfr005Rule();
