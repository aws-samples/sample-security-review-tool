import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { hasIntrinsicFunction } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * ECS-001: Is the ECS service provisioned in a private subnet with ALB/ELB for access?
 *
 * Load Balancers should be your gateway to the cluster. When running an Internet facing service,
 * make sure the solution cluster is in a private subnet and the containers cannot be accessed
 * directly from the Internet. Make sure also that traffic is only allowed from the Load Balancer's
 * Security Group.
 */
export class ECS001Rule extends BaseRule {
  constructor() {
    super(
      'ECS-001',
      'HIGH',
      'ECS service may be directly accessible from the internet without a load balancer',
      ['AWS::ECS::Service']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources || resource.Type !== 'AWS::ECS::Service') {
      return null;
    }

    const networkConfiguration = resource.Properties?.NetworkConfiguration;
    const loadBalancers = resource.Properties?.LoadBalancers;

    if (!networkConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Configure NetworkConfiguration for the ECS service to specify subnets and security groups.'
      );
    }

    const awsvpcConfiguration = networkConfiguration.AwsvpcConfiguration;
    if (!awsvpcConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Use awsvpc network mode with AwsvpcConfiguration to control network access.'
      );
    }

    const subnets = awsvpcConfiguration.Subnets;
    if (!this.hasValidValue(subnets)) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Specify private subnets in the AwsvpcConfiguration.'
      );
    }

    const securityGroups = awsvpcConfiguration.SecurityGroups;
    if (!this.hasValidValue(securityGroups)) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Specify security groups in the AwsvpcConfiguration to control traffic.'
      );
    }

    const assignPublicIp = awsvpcConfiguration.AssignPublicIp;
    if (this.isValueEnabled(assignPublicIp)) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Set AssignPublicIp to DISABLED to prevent direct internet access.'
      );
    }

    if (!loadBalancers || !Array.isArray(loadBalancers) || loadBalancers.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        this.description,
        'Configure a load balancer as the gateway to your ECS service.'
      );
    }

    return null;
  }

  private hasValidValue(value: unknown): boolean {
    if (!value) return false;

    if (Array.isArray(value)) {
      return value.length > 0;
    }

    if (typeof value === 'object' && hasIntrinsicFunction(value)) {
      return true;
    }

    if (typeof value === 'string') {
      return value.trim().length > 0;
    }

    return false;
  }

  private isValueEnabled(value: unknown): boolean {
    if (!value) return false;

    if (typeof value === 'string') {
      return value === 'ENABLED';
    }

    if (typeof value === 'object' && value !== null) {
      const obj = value as Record<string, unknown>;
      if (obj['Ref'] || obj['Fn::GetAtt'] || obj['Fn::Join'] ||
        obj['Fn::Sub'] || obj['Fn::ImportValue']) {
        return false;
      }

      if (obj['Fn::If'] && Array.isArray(obj['Fn::If']) && obj['Fn::If'].length >= 3) {
        return this.isValueEnabled(obj['Fn::If'][1]) || this.isValueEnabled(obj['Fn::If'][2]);
      }
    }

    return false;
  }
}

export default new ECS001Rule();
