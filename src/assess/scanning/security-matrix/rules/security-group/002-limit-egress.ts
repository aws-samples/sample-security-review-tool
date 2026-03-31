import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * NetSg002 Rule: Limit egress rules to specific CIDR ranges
 * 
 * Note: EC2 security group egress checks are now handled by EC2-005 rule
 * This rule defers to EC2-005 for EC2 security group egress checks
 */
export class NetSg002Rule extends BaseRule {
  constructor() {
    super(
      'NET-SG-002',
      'HIGH',
      'Security group allows overly broad egress access. Action: Restrict egress rules to specific CIDR ranges or ports that are required for your application.',
      ['AWS::EC2::SecurityGroup', 'AWS::EC2::SecurityGroupEgress']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // EC2 security group egress checks are now handled by EC2-005 rule
    if (resource.Type === 'AWS::EC2::SecurityGroup' || resource.Type === 'AWS::EC2::SecurityGroupEgress') {
      return null; // Skip these checks as they're handled by EC2-005 rule
    }
    
    // This rule can be extended in the future to handle non-EC2 security group egress rules
    // for other services that might have similar constructs
    
    return null;
  }
}

export default new NetSg002Rule();
