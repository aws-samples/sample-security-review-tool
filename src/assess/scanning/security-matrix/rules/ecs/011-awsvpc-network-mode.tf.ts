import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEcs011Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ECS-011',
      'HIGH',
      'ECS task may not be using awsvpc network mode for proper network isolation',
      ['aws_ecs_task_definition', 'aws_ecs_service']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ecs_task_definition') {
      const networkMode = resource.values?.network_mode;

      if (!networkMode) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          "Set network_mode = \"awsvpc\" in the task definition to enable task networking isolation and security group control."
        );
      }

      if (networkMode !== 'awsvpc') {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          `Change network_mode from '${networkMode}' to 'awsvpc' to enable task networking isolation and security group control.`
        );
      }
    }

    if (resource.type === 'aws_ecs_service') {
      const networkConfiguration = resource.values?.network_configuration;
      if (!networkConfiguration || !Array.isArray(networkConfiguration) || networkConfiguration.length === 0) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Configure network_configuration for the ECS service to specify subnets and security groups, which is required when using awsvpc network mode.'
        );
      }

      const netConfig = networkConfiguration[0];

      const subnets = netConfig.subnets;
      if (!subnets || (Array.isArray(subnets) && subnets.length === 0)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Specify at least one subnet in the network_configuration.'
        );
      }

      const securityGroups = netConfig.security_groups;
      if (!securityGroups || (Array.isArray(securityGroups) && securityGroups.length === 0)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Specify at least one security group in the network_configuration to control network traffic.'
        );
      }

      if (netConfig.assign_public_ip === true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set assign_public_ip = false and use a NAT Gateway for outbound internet access.'
        );
      }
    }

    return null;
  }
}

export default new TfEcs011Rule();
