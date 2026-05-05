import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ECS7 Rule: Is logging enabled for the ECS Task Definition and at minimum using awslogs?
 * 
 * Documentation: "All Solutions must define log configuration for containers."
 * 
 * Note: Basic logging configuration check is covered by Checkov rule CKV_AWS_158,
 * which checks if ECS Task Definitions have log configuration. This rule adds enhanced
 * checks for specific log driver (awslogs) and proper configuration of log options.
 */
export class ECS007Rule extends BaseRule {
  constructor() {
    super(
      'ECS-007',
      'HIGH',
      'ECS task may not have logging enabled',
      ['AWS::ECS::TaskDefinition']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ECS::TaskDefinition') {
      return null;
    }

    const containerDefinitions = resource.Properties?.ContainerDefinitions;
    if (!containerDefinitions || !Array.isArray(containerDefinitions) || containerDefinitions.length === 0) {
      return null; // No container definitions to check
    }

    // Check each container definition for logging configuration
    for (const container of containerDefinitions) {
      const logConfiguration = container.LogConfiguration;

      // Check if log configuration is defined
      if (!logConfiguration) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure LogConfiguration for each container in the task definition.`
        );
      }

      // Check if the log driver is specified
      const logDriver = logConfiguration.LogDriver;
      if (!logDriver) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify a LogDriver in the LogConfiguration for each container.`
        );
      }

      // Check if the log driver is awslogs (recommended)
      if (logDriver !== 'awslogs') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use 'awslogs' as the LogDriver for CloudWatch Logs integration, which is the recommended logging solution for ECS.`
        );
      }

      // Check if awslogs options are properly configured
      const options = logConfiguration.Options;
      if (!options) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure Options for the awslogs LogDriver, including awslogs-group, awslogs-region, and awslogs-stream-prefix.`
        );
      }

      // Check for required awslogs options
      const hasAwsLogsGroup = options['awslogs-group'];
      const hasAwsLogsRegion = options['awslogs-region'];

      if (!hasAwsLogsGroup) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify 'awslogs-group' in the LogConfiguration Options to define the CloudWatch Logs group.`
        );
      }

      if (!hasAwsLogsRegion) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify 'awslogs-region' in the LogConfiguration Options to define the AWS region for CloudWatch Logs.`
        );
      }

      // Recommended but not required options
      const hasAwsLogsStreamPrefix = options['awslogs-stream-prefix'];
      if (!hasAwsLogsStreamPrefix) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Consider specifying 'awslogs-stream-prefix' in the LogConfiguration Options to organize log streams.`
        );
      }
    }

    return null;
  }
}

export default new ECS007Rule();
