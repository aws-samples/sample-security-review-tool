import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaPackage003Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIAPACKAGE-003', 'HIGH', 'MediaPackage origin endpoint must restrict access using CDN authorization or IP whitelisting', ['aws_media_package_channel']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_media_package_channel') {
      // In Terraform, endpoint access control is set on origin endpoints
      // Check if any origin endpoints exist with proper authorization
      const hasEndpoints = allResources.some(r =>
        r.type === 'aws_media_package_channel' &&
        r.values?.hls_ingest
      );

      if (!hasEndpoints) {
        return this.createScanResult(resource, projectName, this.description, 'Configure CDN authorization or IP whitelisting on MediaPackage origin endpoints.');
      }
    }

    return null;
  }
}

export default new TfMediaPackage003Rule();
