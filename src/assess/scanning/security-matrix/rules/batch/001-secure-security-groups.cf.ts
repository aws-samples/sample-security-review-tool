import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * B1 Rule: Secure security groups for Batch compute environments
 * 
 * The Amazon EC2 security groups associated with instances launched in the compute environment 
 * must contain restricted access.
 */
export class Batch001Rule extends BaseRule {
  constructor() {
    super(
      'BATCH-001',
      'HIGH',
      'Batch compute environment uses overly permissive security groups',
      ['AWS::Batch::ComputeEnvironment']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    const computeResources = resource.Properties?.ComputeResources;
    if (!computeResources) {
      return null;
    }

    const securityGroupIds = computeResources.SecurityGroupIds;
    if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        'Add "SecurityGroupIds": [{ "Ref": "YourSecurityGroupLogicalId" }] to the ComputeResources property'
      );
    }

    // Check each security group for overly permissive rules
    for (const sgRef of securityGroupIds) {
      const sg = this.findSecurityGroup(sgRef, allResources);
      if (sg && this.hasOverlyPermissiveRules(sg)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          'In SecurityGroupIngress rules: change "CidrIp": "0.0.0.0/0" to specific IP (e.g., "10.0.0.0/8"), change "CidrIpv6": "::/0" to specific IPv6 range, and set "FromPort" and "ToPort" to same value for single ports (e.g., "FromPort": 22, "ToPort": 22)'
        );
      }
    }

    return null;
  }

  private findSecurityGroup(sgRef: any, resources: CloudFormationResource[]): CloudFormationResource | null {
    if (typeof sgRef === 'string') {
      return resources.find(r => r.Type === 'AWS::EC2::SecurityGroup' && r.LogicalId === sgRef) || null;
    }
    if (typeof sgRef === 'object' && sgRef.Ref) {
      return resources.find(r => r.Type === 'AWS::EC2::SecurityGroup' && r.LogicalId === sgRef.Ref) || null;
    }
    return null;
  }

  private hasOverlyPermissiveRules(sg: CloudFormationResource): boolean {
    const ingressRules = sg.Properties?.SecurityGroupIngress || [];
    
    for (const rule of ingressRules) {
      // Check for 0.0.0.0/0 or ::/0
      if (rule.CidrIp === '0.0.0.0/0' || rule.CidrIpv6 === '::/0') {
        return true;
      }
      
      // Check for overly broad port ranges
      const fromPort = parseInt(rule.FromPort);
      const toPort = parseInt(rule.ToPort);
      if (!isNaN(fromPort) && !isNaN(toPort) && (toPort - fromPort > 100)) {
        return true;
      }
    }

    return false;
  }
}

export default new Batch001Rule();