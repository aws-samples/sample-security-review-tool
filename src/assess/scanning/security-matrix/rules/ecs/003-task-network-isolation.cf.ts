import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { hasIntrinsicFunction } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * ECS-003: Does the ECS task definition use secure network configuration?
 *
 * Task definitions should use awsvpc network mode for network isolation and avoid fixed host ports.
 * Using dynamic port mapping (HostPort: 0 or omitted) allows containers to use ephemeral ports,
 * which is required for proper load balancer target group integration.
 */
export class ECS003Rule extends BaseRule {
  constructor() {
    super(
      'ECS-003',
      'HIGH',
      'ECS task definition uses insecure network configuration',
      ['AWS::ECS::TaskDefinition']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources || resource.Type !== 'AWS::ECS::TaskDefinition') {
      return null;
    }

    const networkMode = resource.Properties?.NetworkMode;
    const containerDefinitions = resource.Properties?.ContainerDefinitions;

    if (!this.isAwsvpcOrIntrinsic(networkMode)) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        "Use 'awsvpc' network mode for task definitions to isolate container networking."
      );
    }

    if (!containerDefinitions || !Array.isArray(containerDefinitions) || containerDefinitions.length === 0) {
      return null;
    }

    for (const container of containerDefinitions) {
      const portMappings = container.PortMappings;
      if (portMappings && Array.isArray(portMappings)) {
        for (const portMapping of portMappings) {
          if (this.isFixedPort(portMapping.HostPort)) {
            return this.createScanResult(
              resource,
              stackName,
              this.description,
              'Use dynamic port mapping by omitting HostPort to allow the container to use ephemeral ports.'
            );
          }
        }
      }
    }

    return null;
  }

  private isAwsvpcOrIntrinsic(value: unknown): boolean {
    if (value === 'awsvpc') {
      return true;
    }

    if (typeof value === 'object' && value !== null && hasIntrinsicFunction(value)) {
      return true;
    }

    return false;
  }

  private isFixedPort(value: unknown): boolean {
    if (value === undefined || value === null) {
      return false;
    }

    if (typeof value === 'number') {
      return value !== 0;
    }

    if (typeof value === 'string') {
      const numValue = parseInt(value, 10);
      return !isNaN(numValue) && numValue !== 0;
    }

    if (typeof value === 'object' && value !== null) {
      const obj = value as Record<string, unknown>;
      if (obj['Ref'] || obj['Fn::GetAtt'] || obj['Fn::Join'] ||
        obj['Fn::Sub'] || obj['Fn::ImportValue']) {
        return false;
      }

      if (obj['Fn::If'] && Array.isArray(obj['Fn::If']) && obj['Fn::If'].length >= 3) {
        return this.isFixedPort(obj['Fn::If'][1]) || this.isFixedPort(obj['Fn::If'][2]);
      }
    }

    return false;
  }
}

export default new ECS003Rule();
