import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfElb004Rule extends BaseTerraformRule {
  constructor() {
    super('ELB-004', 'HIGH', 'Load balancer does not use multiple AZs or Cross-Zone Load Balancing is not enabled', ['aws_lb', 'aws_elb']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_elb') {
      const subnets = resource.values?.subnets;
      const azs = resource.values?.availability_zones;
      const count = subnets?.length || azs?.length || 0;

      if (count < 2) {
        return this.createScanResult(resource, projectName, this.description, 'Configure at least 2 subnets or availability_zones for high availability.');
      }

      if (resource.values?.cross_zone_load_balancing !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Set cross_zone_load_balancing = true.');
      }
    }

    if (resource.type === 'aws_lb') {
      const subnets = resource.values?.subnets;
      const subnetMapping = resource.values?.subnet_mapping;
      const count = subnets?.length || subnetMapping?.length || 0;

      if (count < 2) {
        return this.createScanResult(resource, projectName, this.description, 'Configure at least 2 subnets for high availability.');
      }

      const isNlb = resource.values?.load_balancer_type === 'network';
      if (isNlb && resource.values?.enable_cross_zone_load_balancing !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Set enable_cross_zone_load_balancing = true for Network Load Balancer.');
      }
    }

    return null;
  }
}

export default new TfElb004Rule();
