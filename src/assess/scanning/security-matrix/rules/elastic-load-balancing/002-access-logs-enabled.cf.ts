import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ELB2 Rule: Enable ELB/ALB access logs
 * 
 * Solutions must use access logs to allow customers to analyze traffic patterns 
 * and identify and troubleshoot security issues.
 */
export class Elb002Rule extends BaseRule {
  constructor() {
    super(
      'ELB-002',
      'HIGH',
      'Load balancer does not have access logs enabled',
      ['AWS::ElasticLoadBalancing::LoadBalancer', 'AWS::ElasticLoadBalancingV2::LoadBalancer']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::ElasticLoadBalancing::LoadBalancer') {
      // Classic Load Balancer
      const accessLoggingPolicy = resource.Properties?.AccessLoggingPolicy;
      if (!accessLoggingPolicy || !accessLoggingPolicy.Enabled) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Enable access logging by setting AccessLoggingPolicy.Enabled to true and specify S3BucketName`
        );
      }
    } else if (resource.Type === 'AWS::ElasticLoadBalancingV2::LoadBalancer') {
      // Application/Network Load Balancer
      const loadBalancerAttributes = resource.Properties?.LoadBalancerAttributes;
      if (!loadBalancerAttributes || !Array.isArray(loadBalancerAttributes)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add LoadBalancerAttributes with access_logs.s3.enabled set to true`
        );
      }

      const accessLogsEnabled = loadBalancerAttributes.find((attr: any) => 
        attr.Key === 'access_logs.s3.enabled'
      );

      if (!accessLogsEnabled || accessLogsEnabled.Value !== 'true') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set access_logs.s3.enabled to true in LoadBalancerAttributes and specify access_logs.s3.bucket`
        );
      }
    }

    return null;
  }
}

export default new Elb002Rule();