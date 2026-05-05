import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfAs006Rule extends BaseTerraformRule {
  constructor() {
    super('AS-006', 'HIGH', 'Auto Scaling Group does not span multiple Availability Zones', ['aws_autoscaling_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_autoscaling_group') {
      const azs = resource.values?.availability_zones;
      const vpcZoneIdentifier = resource.values?.vpc_zone_identifier;

      if (azs && Array.isArray(azs)) {
        if (azs.length < 2) {
          return this.createScanResult(resource, projectName, this.description, 'Add at least 2 availability zones for high availability.');
        }
      } else if (vpcZoneIdentifier && Array.isArray(vpcZoneIdentifier)) {
        if (vpcZoneIdentifier.length < 2) {
          return this.createScanResult(resource, projectName, this.description, 'Add at least 2 subnet IDs to vpc_zone_identifier to span multiple Availability Zones.');
        }
      } else {
        return this.createScanResult(resource, projectName, this.description, 'Set vpc_zone_identifier with at least 2 subnet IDs to span multiple Availability Zones.');
      }
    }

    return null;
  }
}

export default new TfAs006Rule();
