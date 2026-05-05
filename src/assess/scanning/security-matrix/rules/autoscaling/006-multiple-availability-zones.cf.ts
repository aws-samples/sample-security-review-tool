import { ScanResult } from '../../../base-scanner.js';
import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';

/**
 * AS006 Rule: Implement ASG scaling to multiple Availability Zones (AZs).
 * 
 * Documentation: "Solution ASGs must span across multiple Availability Zones (AZs) within an AWS region to expand 
 * the availability of the auto-scaled applications. If one AZ goes down, instances in the other AZs will still be 
 * available to serve traffic. This improves resilience against DDoS attacks or network outages."
 */
export class AS006Rule extends BaseRule {
  constructor() {
    super(
      'AS-006',
      'HIGH',
      'Auto Scaling Group does not span multiple Availability Zones',
      ['AWS::AutoScaling::AutoScalingGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
      return null;
    }

    const availabilityZones = resource.Properties?.AvailabilityZones;
    const vpcZoneIdentifier = resource.Properties?.VPCZoneIdentifier;

    // Check availability zones
    if (availabilityZones && Array.isArray(availabilityZones)) {
      if (availabilityZones.length < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add at least 2 availability zones to AvailabilityZones property for high availability.`
        );
      }
    }
    // Check VPC subnets (which implicitly define AZs)
    else if (vpcZoneIdentifier && Array.isArray(vpcZoneIdentifier)) {
      if (vpcZoneIdentifier.length < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add at least 2 subnet IDs to VPCZoneIdentifier property to span multiple Availability Zones.`
        );
      }
    }
    // No AZ configuration found
    else {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add VPCZoneIdentifier property with at least 2 subnet IDs to span multiple Availability Zones.`
      );
    }

    return null;
  }
}

export default new AS006Rule();