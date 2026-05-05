import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ML3 Rule: Restrict access to AWS MediaLive input security groups by allowlisting specific ingress.
 * 
 * Use an implicitly-deny approach to MediaLive access. A lack of restrictions could lead 
 * to unintended access.
 */
export class MEDIALIVE003Rule extends BaseRule {
  constructor() {
    super(
      'MEDIALIVE-003',
      'HIGH',
      'MediaLive input security group must have specific whitelist rules to restrict access',
      ['AWS::MediaLive::InputSecurityGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::MediaLive::InputSecurityGroup') {
      return null;
    }

    const properties = resource.Properties || {};
    const whitelistRules = properties.WhitelistRules;
    
    if (!whitelistRules || !Array.isArray(whitelistRules) || whitelistRules.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add WhitelistRules array with CIDR blocks that restrict access to known source networks. Analyze the infrastructure context to determine appropriate IP ranges.'
      );
    }

    // Check for overly permissive rules
    for (const rule of whitelistRules) {
      if (rule.Cidr === '0.0.0.0/0') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          'Replace "0.0.0.0/0" with specific CIDR blocks based on the application\'s network requirements. Consider VPC CIDR ranges, office networks, or specific service endpoints.'
        );
      }
    }

    return null;
  }
}

export default new MEDIALIVE003Rule();