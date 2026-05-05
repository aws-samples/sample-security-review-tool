import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Neptune005Rule extends BaseRule {
  constructor() {
    super(
      'NEPTUNE-005',
      'HIGH',
      'Neptune database security group allows unrestricted ingress from 0.0.0.0/0',
      ['AWS::Neptune::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure VpcSecurityGroupIds with security groups that restrict access and do not allow ingress from 0.0.0.0/0.`
      );
    }

    if (resource.Type === 'AWS::Neptune::DBCluster') {
      return this.evaluateNeptuneCluster(resource, stackName, allResources || []);
    }

    return null;
  }

  private evaluateNeptuneCluster(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    const vpcSecurityGroupIds = resource.Properties.VpcSecurityGroupIds;

    // If no VpcSecurityGroupIds specified, Neptune uses the default security group
    // We should flag this as we can't verify the default security group configuration
    if (!vpcSecurityGroupIds) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify explicit VpcSecurityGroupIds with security groups that restrict access and do not allow ingress from 0.0.0.0/0.`
      );
    }

    // Handle CloudFormation intrinsic functions for the entire array (e.g., !Ref Parameter that resolves to an array)
    if (typeof vpcSecurityGroupIds === 'object' && !Array.isArray(vpcSecurityGroupIds)) {
      // This would be something like !Ref SecurityGroupsParameter - can't validate parameters
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Use explicit security group arrays in VpcSecurityGroupIds rather than CloudFormation parameters that cannot be validated at scan time.`
      );
    }

    // VpcSecurityGroupIds must be an array (CloudFormation enforces this)
    if (!Array.isArray(vpcSecurityGroupIds)) {
      // This should never happen with valid CloudFormation, but handle gracefully
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set VpcSecurityGroupIds to an array of security group IDs that restrict access and do not allow ingress from 0.0.0.0/0.`
      );
    }

    // Check if the array is empty
    if (vpcSecurityGroupIds.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add security group IDs to VpcSecurityGroupIds array that restrict access and do not allow ingress from 0.0.0.0/0.`
      );
    }

    // Check each security group referenced
    const securityGroupIssues = this.checkSecurityGroups(vpcSecurityGroupIds, allResources);

    if (securityGroupIssues.length > 0) {
      const issueMessage = securityGroupIssues.join(', ');
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `${issueMessage}.`
      );
    }

    // All security groups appear to be compliant
    return null;
  }

  private checkSecurityGroups(securityGroupIds: any[], allResources: CloudFormationResource[]): string[] {
    const issues: string[] = [];

    for (const sgId of securityGroupIds) {
      // Handle CloudFormation intrinsic functions within the array
      if (typeof sgId === 'object') {
        const resolvedSgId = this.resolveSecurityGroupReference(sgId, allResources);
        if (resolvedSgId === null) {
          // Could not resolve to a template resource, likely a parameter or external reference
          issues.push('Use explicit security group IDs rather than CloudFormation functions that cannot be validated at scan time');
          continue;
        }
        // Use the resolved security group resource for validation
        const securityGroup = resolvedSgId;
        const hasUnrestrictedIngress = this.hasUnrestrictedIngress(securityGroup);
        if (hasUnrestrictedIngress) {
          issues.push(`Remove ingress rules allowing 0.0.0.0/0 from security group '${securityGroup.LogicalId}'`);
        }
        continue;
      }

      // Find the security group resource in the template
      const securityGroup = this.findSecurityGroupById(sgId, allResources);

      if (securityGroup) {
        // Check if this security group allows 0.0.0.0/0 ingress
        const hasUnrestrictedIngress = this.hasUnrestrictedIngress(securityGroup);
        if (hasUnrestrictedIngress) {
          issues.push(`Remove ingress rules allowing 0.0.0.0/0 from security group '${sgId}'`);
        }
      } else {
        // External security group - can't verify, so flag it
        issues.push(`Ensure external security group '${sgId}' does not allow ingress from 0.0.0.0/0`);
      }
    }

    return issues;
  }

  private resolveSecurityGroupReference(sgRef: any, allResources: CloudFormationResource[]): CloudFormationResource | null {
    // Handle !Ref references
    if (sgRef.Ref) {
      const referencedResource = allResources.find(resource => resource.LogicalId === sgRef.Ref);
      if (referencedResource && referencedResource.Type === 'AWS::EC2::SecurityGroup') {
        return referencedResource;
      }
      // If not found or not a security group, it's likely a parameter
      return null;
    }

    // Handle !GetAtt references (e.g., !GetAtt MySecurityGroup.GroupId)
    if (sgRef['Fn::GetAtt'] || sgRef.GetAtt) {
      const getAttValue = sgRef['Fn::GetAtt'] || sgRef.GetAtt;
      const resourceName = Array.isArray(getAttValue) ? getAttValue[0] : getAttValue.split('.')[0];
      const referencedResource = allResources.find(resource => resource.LogicalId === resourceName);
      if (referencedResource && referencedResource.Type === 'AWS::EC2::SecurityGroup') {
        return referencedResource;
      }
      // If not found or not a security group, it's likely external
      return null;
    }

    // Handle other intrinsic functions - can't validate
    return null;
  }

  private findSecurityGroupById(sgId: string, allResources: CloudFormationResource[]): CloudFormationResource | null {
    return allResources.find(resource =>
      resource.Type === 'AWS::EC2::SecurityGroup' &&
      (resource.LogicalId === sgId || resource.Properties?.GroupName === sgId)
    ) || null;
  }

  private hasUnrestrictedIngress(securityGroup: CloudFormationResource): boolean {
    if (!securityGroup.Properties || !securityGroup.Properties.SecurityGroupIngress) {
      return false;
    }

    const ingressRules = securityGroup.Properties.SecurityGroupIngress;

    // Handle both single rule and array of rules
    const rules = Array.isArray(ingressRules) ? ingressRules : [ingressRules];

    for (const rule of rules) {
      // Check for 0.0.0.0/0 in CidrIp
      if (rule.CidrIp === '0.0.0.0/0') {
        return true;
      }

      // Check for 0.0.0.0/0 in CidrIpv6 (though less common)
      if (rule.CidrIpv6 === '::/0') {
        return true;
      }

      // Handle CloudFormation intrinsic functions in CIDR
      if (typeof rule.CidrIp === 'object' || typeof rule.CidrIpv6 === 'object') {
        // Can't verify at scan time, but this is already flagged by the parent check
        continue;
      }
    }

    return false;
  }
}

export default new Neptune005Rule();