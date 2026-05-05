import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfCfr003Rule extends BaseTerraformRule {
  constructor() {
    super('CFR-003', 'HIGH', 'CloudFront distribution does not have access logging enabled', ['aws_cloudfront_distribution']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_cloudfront_distribution') {
      const loggingConfig = resource.values?.logging_config;
      if (!loggingConfig || !loggingConfig.bucket) {
        return this.createScanResult(resource, projectName, this.description, 'Add logging_config block with bucket to enable access logging.');
      }
    }

    return null;
  }
}

export default new TfCfr003Rule();
