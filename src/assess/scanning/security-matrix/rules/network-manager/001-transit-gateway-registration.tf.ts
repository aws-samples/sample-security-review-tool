import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNetMgr001Rule extends BaseTerraformRule {
  constructor() {
    super('NETMGR-001', 'HIGH', 'Transit Gateway is not registered with Network Manager for centralized management', ['aws_ec2_transit_gateway']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ec2_transit_gateway') {
      const hasRegistration = allResources.some(r =>
        r.type === 'aws_networkmanager_transit_gateway_registration'
      );

      if (!hasRegistration) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_networkmanager_transit_gateway_registration to register the Transit Gateway with Network Manager.');
      }
    }

    return null;
  }
}

export default new TfNetMgr001Rule();
