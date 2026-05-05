import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNetVpc001Rule extends BaseTerraformRule {
  constructor() {
    super('NET-VPC-001', 'HIGH', 'VPC configuration does not use multiple availability zones', ['aws_vpc']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_vpc') {
      const subnets = allResources.filter(r =>
        r.type === 'aws_subnet' &&
        r.values?.vpc_id === resource.values?.id
      );

      if (subnets.length === 0) {
        return null;
      }

      const azs = new Set<string>();
      for (const subnet of subnets) {
        const az = subnet.values?.availability_zone;
        if (az) {
          azs.add(az);
        }
      }

      if (azs.size < 2) {
        return this.createScanResult(resource, projectName, `VPC has subnets in only ${azs.size} availability zone(s)`, 'Create subnets in at least two different availability zones to ensure high availability.');
      }
    }

    return null;
  }
}

export default new TfNetVpc001Rule();
