import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCfr004Rule extends BaseTerraformRule {
  constructor() {
    super('CFR-004', 'HIGH', 'CloudFront distribution does not enforce HTTPS-only viewer connections', ['aws_cloudfront_distribution']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_cloudfront_distribution') {
      const defaultCacheBehavior = resource.values?.default_cache_behavior;
      if (defaultCacheBehavior) {
        const viewerProtocolPolicy = defaultCacheBehavior.viewer_protocol_policy;
        if (viewerProtocolPolicy === 'allow-all') {
          return this.createScanResult(resource, projectName, this.description, 'Set viewer_protocol_policy to "redirect-to-https" or "https-only" in default_cache_behavior.');
        }
      }

      const orderedCacheBehaviors = resource.values?.ordered_cache_behavior;
      if (Array.isArray(orderedCacheBehaviors)) {
        for (const behavior of orderedCacheBehaviors) {
          if (behavior.viewer_protocol_policy === 'allow-all') {
            return this.createScanResult(resource, projectName, this.description, 'Set viewer_protocol_policy to "redirect-to-https" or "https-only" in all cache behaviors.');
          }
        }
      }
    }

    return null;
  }
}

export default new TfCfr004Rule();
