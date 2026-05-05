import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNetVpc002Rule extends BaseTerraformRule {
  constructor() {
    super('NET-VPC-002', 'HIGH', 'Route table has insecure routing configuration', ['aws_route_table', 'aws_route']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_route') {
      const destinationCidrBlock = resource.values?.destination_cidr_block;
      const gatewayId = resource.values?.gateway_id;

      if (destinationCidrBlock === '0.0.0.0/0' && gatewayId && typeof gatewayId === 'string' && gatewayId.startsWith('igw-')) {
        return this.createScanResult(resource, projectName, 'Route has a default route to an Internet Gateway - verify it is not associated with private subnets', 'Use a NAT Gateway instead of an Internet Gateway for outbound internet access from private subnets.');
      }
    }

    if (resource.type === 'aws_route_table') {
      const routes = resource.values?.route;
      if (Array.isArray(routes)) {
        for (const route of routes) {
          if (route.cidr_block === '0.0.0.0/0' && route.gateway_id && typeof route.gateway_id === 'string' && route.gateway_id.startsWith('igw-')) {
            return this.createScanResult(resource, projectName, 'Route table has a default route to an Internet Gateway - verify it is not associated with private subnets', 'Create a separate route table for private subnets that uses a NAT Gateway.');
          }
        }
      }
    }

    return null;
  }
}

export default new TfNetVpc002Rule();
