import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk009Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-009', 'HIGH', 'MSK cluster should have CloudTrail monitoring configured', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const cloudTrails = allResources.filter(r => r.type === 'aws_cloudtrail');
      if (cloudTrails.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Add an aws_cloudtrail resource with management events enabled to monitor MSK API calls.');
      }
    }

    return null;
  }
}

export default new TfMsk009Rule();
