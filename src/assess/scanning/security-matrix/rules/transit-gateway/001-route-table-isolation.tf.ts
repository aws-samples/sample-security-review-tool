import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfTg001Rule extends BaseTerraformRule {
  constructor() {
    super('TG-001', 'HIGH', 'Transit Gateway configuration does not properly isolate VPCs using separate route tables', ['aws_ec2_transit_gateway']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ec2_transit_gateway') {
      const defaultRouteTableAssociation = resource.values?.default_route_table_association;
      if (defaultRouteTableAssociation === 'enable') {
        return this.createScanResult(resource, projectName, 'Transit Gateway has default route table association enabled', 'Set default_route_table_association = "disable" and create explicit route tables for VPC isolation.');
      }

      const defaultRouteTablePropagation = resource.values?.default_route_table_propagation;
      if (defaultRouteTablePropagation === 'enable') {
        return this.createScanResult(resource, projectName, 'Transit Gateway has default route table propagation enabled', 'Set default_route_table_propagation = "disable" and configure explicit route propagation.');
      }

      const routeTables = allResources.filter(r =>
        r.type === 'aws_ec2_transit_gateway_route_table'
      );

      if (routeTables.length < 2) {
        return this.createScanResult(resource, projectName, this.description, 'Create at least 2 aws_ec2_transit_gateway_route_table resources for proper VPC isolation.');
      }
    }

    return null;
  }
}

export default new TfTg001Rule();
