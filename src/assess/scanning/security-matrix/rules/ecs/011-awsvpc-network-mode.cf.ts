import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ECS11 Rule: Use awsvpc network mode to isolate, route and control network traffic for tasks and network resources
 * 
 * Documentation: "Security groups should also be used to control traffic between tasks and other resources 
 * within the Amazon VPC such as Amazon RDS databases. See:
 * https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security-network.html#security-network-recommendations"
 * 
 * Note: Basic network mode check is partially covered by Checkov rule CKV_AWS_224,
 * which checks if ECS Task Definitions use a specific non-default launch type.
 * This rule adds enhanced checks for awsvpc network mode specifically, proper security group
 * configuration, and subnet configuration in the service.
 */
export class ECS011Rule extends BaseRule {
  constructor() {
    super(
      'ECS-011',
      'HIGH',
      'ECS task may not be using awsvpc network mode for proper network isolation',
      ['AWS::ECS::TaskDefinition', 'AWS::ECS::Service']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // For ECS TaskDefinition, check if it's using awsvpc network mode
    if (resource.Type === 'AWS::ECS::TaskDefinition') {
      const networkMode = resource.Properties?.NetworkMode;

      // Check if network mode is specified
      if (!networkMode) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify NetworkMode as 'awsvpc' in the task definition to enable task networking isolation and security group control.`
        );
      }

      // Handle intrinsic functions in NetworkMode
      if (typeof networkMode === 'object') {
        // If it's an intrinsic function, we'll assume it's valid
        return null;
      }

      // Check if network mode is awsvpc
      if (networkMode !== 'awsvpc') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Change NetworkMode from '${networkMode}' to 'awsvpc' to enable task networking isolation and security group control.`
        );
      }
    }

    // For ECS Service, check if it has network configuration when using awsvpc network mode
    if (resource.Type === 'AWS::ECS::Service') {
      // We need to check if the task definition uses awsvpc network mode
      // Since we can't directly access the task definition's properties here,
      // we'll check if the service has network configuration, which is required for awsvpc

      const networkConfiguration = resource.Properties?.NetworkConfiguration;

      // If network configuration is missing, it might indicate the service is not using awsvpc
      if (!networkConfiguration) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure NetworkConfiguration for the ECS service to specify subnets and security groups, which is required when using awsvpc network mode.`
        );
      }

      // Check if awsvpcConfiguration is specified
      const awsvpcConfiguration = networkConfiguration.AwsvpcConfiguration;
      if (!awsvpcConfiguration) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure AwsvpcConfiguration within NetworkConfiguration to specify subnets and security groups.`
        );
      }

      // Check if subnets are specified
      const subnets = awsvpcConfiguration.Subnets;
      if (!subnets) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify at least one subnet in the AwsvpcConfiguration.`
        );
      }

      // Handle intrinsic functions in Subnets
      if (typeof subnets === 'object' && !Array.isArray(subnets)) {
        // If it's an intrinsic function, we'll assume it's valid
        return null;
      }

      // Check if subnets array is empty
      if (Array.isArray(subnets) && subnets.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify at least one subnet in the AwsvpcConfiguration.`
        );
      }

      // Check if security groups are specified
      const securityGroups = awsvpcConfiguration.SecurityGroups;
      if (!securityGroups) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify at least one security group in the AwsvpcConfiguration to control network traffic.`
        );
      }

      // Handle intrinsic functions in SecurityGroups
      if (typeof securityGroups === 'object' && !Array.isArray(securityGroups)) {
        // If it's an intrinsic function, we'll assume it's valid
        return null;
      }

      // Check if security groups array is empty
      if (Array.isArray(securityGroups) && securityGroups.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify at least one security group in the AwsvpcConfiguration to control network traffic.`
        );
      }

      // Check if AssignPublicIp is set to DISABLED for better security
      const assignPublicIp = awsvpcConfiguration.AssignPublicIp;

      // Handle intrinsic functions in AssignPublicIp
      if (typeof assignPublicIp === 'object') {
        // If it's an intrinsic function, we'll assume it's valid
        return null;
      }

      if (assignPublicIp === 'ENABLED') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set AssignPublicIp to DISABLED and use a NAT Gateway for outbound internet access.`
        );
      }
    }

    return null;
  }
}

export default new ECS011Rule();
