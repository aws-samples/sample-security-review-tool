import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaStore010Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIASTORE-010', 'HIGH', 'MediaStore container must implement object lifecycle policy to govern object storage duration', ['aws_media_store_container']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_media_store_container') {
      if (!resource.values?.lifecycle_policy) {
        return this.createScanResult(resource, projectName, this.description, 'Set lifecycle_policy with rules to govern object expiration.');
      }
    }

    return null;
  }
}

export default new TfMediaStore010Rule();
