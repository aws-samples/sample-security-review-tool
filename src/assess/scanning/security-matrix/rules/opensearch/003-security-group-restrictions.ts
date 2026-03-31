import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * ESH3 Rule: Ensure the security group attached to the OpenSearch cluster restricts network access.
 */
export class ESH003Rule extends BaseRule {
  constructor() {
    super(
      'ESH-003',
      'HIGH',
      'OpenSearch security group allows unrestricted access',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const vpcOptions = resource.Properties?.VPCOptions;

    if (!vpcOptions || !vpcOptions.SecurityGroupIds) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add SecurityGroupIds to VPCOptions with restricted access rules.`
      );
    }

    // If we have all resources, check if the security groups actually restrict access
    if (allResources && Array.isArray(vpcOptions.SecurityGroupIds) && vpcOptions.SecurityGroupIds.length > 0) {
      const securityGroupResources = this.findSecurityGroupResources(vpcOptions.SecurityGroupIds, allResources);

      // If we found security groups, check if they have overly permissive rules
      if (securityGroupResources.length > 0) {
        const permissiveGroups = this.findPermissiveSecurityGroups(securityGroupResources);
        if (permissiveGroups.length > 0) {
          const sgNames = permissiveGroups.map(sg => sg.LogicalId).join(', ');
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Security groups [${sgNames}] have overly permissive ingress rules. Limit access to specific IP ranges or security groups.`
          );
        }
      }
    }

    return null;
  }
  /**
   * Find security group resources from their IDs
   */
  private findSecurityGroupResources(securityGroupIds: any[], allResources: CloudFormationResource[]): CloudFormationResource[] {
    const resolver = new CloudFormationResolver(allResources);
    const securityGroups: CloudFormationResource[] = [];

    // Get all security group resources
    const sgResources = allResources.filter(r =>
      r.Type === 'AWS::EC2::SecurityGroup'
    );

    // Check for direct references or through Ref intrinsic function
    for (const sgId of securityGroupIds) {
      // Handle direct logical ID
      const directMatch = sgResources.find(sg => sg.LogicalId === sgId);
      if (directMatch) {
        securityGroups.push(directMatch);
        continue;
      }

      // Handle Ref: intrinsic function
      if (typeof sgId === 'object' && sgId.Ref) {
        const refMatch = sgResources.find(sg => sg.LogicalId === sgId.Ref);
        if (refMatch) {
          securityGroups.push(refMatch);
          continue;
        }
      }
    }

    return securityGroups;
  }

  /**
   * Check if any security groups have overly permissive ingress rules
   */
  private findPermissiveSecurityGroups(securityGroups: CloudFormationResource[]): CloudFormationResource[] {
    return securityGroups.filter(sg => {
      const ingressRules = sg.Properties?.SecurityGroupIngress || [];

      // Check if any ingress rule is overly permissive
      return ingressRules.some((rule: any) => {
        // Check for CIDR that allows wide access
        if (rule.CidrIp === '0.0.0.0/0' || rule.CidrIp === '::/0') {
          return true;
        }

        // Check for CidrIpv6 that allows wide access
        if (rule.CidrIpv6 === '::/0') {
          return true;
        }

        // Check for missing CIDR or source security group
        if (!rule.CidrIp && !rule.CidrIpv6 && !rule.SourceSecurityGroupId && !rule.SourceSecurityGroupName) {
          return true;
        }

        return false;
      });
    });
  }
}

export default new ESH003Rule();
