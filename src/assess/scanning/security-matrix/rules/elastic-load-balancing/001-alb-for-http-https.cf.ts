import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ELB1 Rule: Use ALB for HTTP/HTTPS applications
 * 
 * HTTP/HTTPS applications (monolithic or containerized) should use the Application Load Balancer (ALB) 
 * instead of Classic Load Balancer (ELB) for enhanced incoming traffic distribution, better performance and lower costs.
 */
export class Elb001Rule extends BaseRule {
  constructor() {
    super(
      'ELB-001',
      'HIGH',
      'Classic Load Balancer is used for HTTP/HTTPS traffic instead of Application Load Balancer',
      ['AWS::ElasticLoadBalancing::LoadBalancer']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ElasticLoadBalancing::LoadBalancer') {
      return null;
    }

    const listeners = resource.Properties?.Listeners;
    if (!listeners || !Array.isArray(listeners)) {
      return null;
    }

    // Check if any listener uses HTTP or HTTPS protocol
    const hasHttpHttps = listeners.some((listener: any) => {
      const protocol = listener.Protocol;
      return protocol === 'HTTP' || protocol === 'HTTPS';
    });

    if (hasHttpHttps) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Replace Classic Load Balancer with Application Load Balancer (AWS::ElasticLoadBalancingV2::LoadBalancer with Type: application) for HTTP/HTTPS traffic`
      );
    }

    return null;
  }
}

export default new Elb001Rule();