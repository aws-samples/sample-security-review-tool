import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * AS001 Rule: Discuss and implement ASG cooldown periods.
 * 
 * Documentation: "Use a cooldown period to temporarily suspend any scaling activities in order to allow 
 * the newly launched Amazon EC2 instances some time to start handling the application traffic."
 */
export class AS001Rule extends BaseRule {
  constructor() {
    super(
      'AS-001',
      'HIGH',
      'Auto Scaling Group does not have cooldown period configured',
      ['AWS::AutoScaling::AutoScalingGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
      return null;
    }

    const cooldown = resource.Properties?.Cooldown;
    const defaultCooldown = resource.Properties?.DefaultCooldown;

    if (!cooldown && !defaultCooldown) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set DefaultCooldown property to 300 seconds to allow newly launched instances time to start handling traffic.`
      );
    }

    return null;
  }
}

export default new AS001Rule();