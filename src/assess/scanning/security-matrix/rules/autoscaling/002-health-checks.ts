import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * AS002 Rule: Discuss and configure ASG health checks.
 * 
 * Documentation: "Someone should own and act on failed health checks. Make sure to decide on useful grace periods."
 */
export class AS002Rule extends BaseRule {
  constructor() {
    super(
      'AS-002',
      'HIGH',
      'Auto Scaling Group does not have health check configuration',
      ['AWS::AutoScaling::AutoScalingGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
      return null;
    }

    const healthCheckType = resource.Properties?.HealthCheckType;
    const healthCheckGracePeriod = resource.Properties?.HealthCheckGracePeriod;

    if (!healthCheckType || healthCheckType === 'EC2') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set HealthCheckType to 'ELB' and HealthCheckGracePeriod to 300 seconds for comprehensive health monitoring.`
      );
    }

    if (healthCheckType === 'ELB' && !healthCheckGracePeriod) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set HealthCheckGracePeriod to 300 seconds to allow instances time to initialize before health checks begin.`
      );
    }

    return null;
  }
}

export default new AS002Rule();