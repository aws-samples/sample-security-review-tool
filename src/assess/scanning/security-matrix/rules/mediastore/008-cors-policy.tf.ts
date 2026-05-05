import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaStore008Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIASTORE-008', 'HIGH', 'MediaStore container must implement CORS policy to explicitly allow/restrict access', ['aws_media_store_container']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_media_store_container') {
      const hasCorsPolicy = allResources.some(r =>
        r.type === 'aws_media_store_container_policy' &&
        r.values?.container_name === resource.values?.name
      );

      // In Terraform, CORS is set via aws_media_store_container_policy or inline
      if (!resource.values?.cors_policy && !hasCorsPolicy) {
        return this.createScanResult(resource, projectName, this.description, 'Add CORS policy to restrict access to legitimate domains.');
      }
    }

    return null;
  }
}

export default new TfMediaStore008Rule();
