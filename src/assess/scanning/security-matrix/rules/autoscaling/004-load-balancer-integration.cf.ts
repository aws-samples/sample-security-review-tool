import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * AS004 Rule: Implement AWS Elastic Load Balancer (ELB) or Classic Load Balancer (CLB) to distribute application loads.
 * 
 * Documentation: "There are four types of ELBs in addition to Classic Load Balancer."
 */
export class AS004Rule extends BaseRule {
  constructor() {
    super(
      'AS-004',
      'HIGH',
      'Auto Scaling Group is not integrated with any load balancer',
      ['AWS::AutoScaling::AutoScalingGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
      return null;
    }

    const targetGroupARNs = resource.Properties?.TargetGroupARNs;
    const loadBalancerNames = resource.Properties?.LoadBalancerNames;

    if ((!targetGroupARNs || targetGroupARNs.length === 0) && 
        (!loadBalancerNames || loadBalancerNames.length === 0)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add TargetGroupARNs property with target group ARNs for Application/Network Load Balancer integration.`
      );
    }

    return null;
  }
}

export default new AS004Rule();