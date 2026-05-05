import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ECS-001',
      'HIGH',
      'ECS service may be directly accessible from the internet without a load balancer',
      ['aws_ecs_service']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_ecs_service') return null;

    const networkConfiguration = resource.values?.network_configuration;
    if (!networkConfiguration || !Array.isArray(networkConfiguration) || networkConfiguration.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Configure network_configuration for the ECS service to specify subnets and security groups.'
      );
    }

    const netConfig = networkConfiguration[0];

    const subnets = netConfig.subnets;
    if (!subnets || !Array.isArray(subnets) || subnets.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Specify private subnets in the network_configuration.'
      );
    }

    const securityGroups = netConfig.security_groups;
    if (!securityGroups || !Array.isArray(securityGroups) || securityGroups.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Specify security_groups in the network_configuration to control traffic.'
      );
    }

    if (netConfig.assign_public_ip === true) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Set assign_public_ip = false to prevent direct internet access.'
      );
    }

    const loadBalancers = resource.values?.load_balancer;
    if (!loadBalancers || !Array.isArray(loadBalancers) || loadBalancers.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Configure a load_balancer block as the gateway to your ECS service.'
      );
    }

    return null;
  }
}

export default new TfEcs001Rule();
