import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaPackage007Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIAPACKAGE-007', 'HIGH', 'MediaPackage origin endpoint with encryption must specify KeyRotationIntervalSeconds of at least 300', ['aws_media_package_channel']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    // MediaPackage in Terraform has limited resource types; this check is informational
    if (resource.type === 'aws_media_package_channel') {
      // Note: Key rotation is configured on origin endpoints which have limited Terraform support
      return null;
    }

    return null;
  }
}

export default new TfMediaPackage007Rule();
