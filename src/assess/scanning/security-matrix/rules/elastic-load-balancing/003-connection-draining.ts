import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ELB3 Rule: Enable connection draining for Classic Load Balancer
 * 
 * With Connection Draining feature enabled, if an EC2 backend instance fails health checks 
 * the Elastic Load Balancer will not send any new requests to the unhealthy instance. 
 * However, it will still allow existing (in-flight) requests to complete for the duration of the configured timeout.
 */
export class Elb003Rule extends BaseRule {
  constructor() {
    super(
      'ELB-003',
      'HIGH',
      'Classic Load Balancer does not have connection draining enabled',
      ['AWS::ElasticLoadBalancing::LoadBalancer']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::ElasticLoadBalancing::LoadBalancer') {
      return null;
    }

    const connectionDrainingPolicy = resource.Properties?.ConnectionDrainingPolicy;
    if (!connectionDrainingPolicy || !connectionDrainingPolicy.Enabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable connection draining by setting ConnectionDrainingPolicy.Enabled to true and specify Timeout (recommended: 300 seconds)`
      );
    }

    return null;
  }
}

export default new Elb003Rule();