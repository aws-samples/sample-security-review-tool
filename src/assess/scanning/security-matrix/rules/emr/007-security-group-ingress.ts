import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EMR7 Rule: The security group for the EMR cluster does not allow open ingress.
 * 
 * Documentation: "The cluster should only allow access from a specific IP address range 
 * or EC2 security group on port 22."
 */
export class EMR007Rule extends BaseRule {
  constructor() {
    super(
      'EMR-007',
      'HIGH',
      'EMR cluster security group allows open ingress (0.0.0.0/0)',
      ['AWS::EMR::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type !== 'AWS::EMR::Cluster') {
      return null;
    }

    // EMR7: Check security groups for open ingress
    const additionalMasterSecurityGroups = resource.Properties?.Instances?.AdditionalMasterSecurityGroups;
    const additionalSlaveSecurityGroups = resource.Properties?.Instances?.AdditionalSlaveSecurityGroups;
    const emrManagedMasterSecurityGroup = resource.Properties?.Instances?.EmrManagedMasterSecurityGroup;
    const emrManagedSlaveSecurityGroup = resource.Properties?.Instances?.EmrManagedSlaveSecurityGroup;

    if (!allResources) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Ensure security groups referenced by EMR cluster do not allow open ingress (0.0.0.0/0).`
      );
    }

    // Collect all security group references
    const securityGroupIds = [
      ...(additionalMasterSecurityGroups || []),
      ...(additionalSlaveSecurityGroups || []),
      emrManagedMasterSecurityGroup,
      emrManagedSlaveSecurityGroup
    ].filter(Boolean);

    // Check each security group for open ingress
    for (const sgId of securityGroupIds) {
      const securityGroup = allResources.find(r => 
        r.Type === 'AWS::EC2::SecurityGroup' && 
        (r.LogicalId === sgId || r.Properties?.GroupId === sgId)
      );

      if (securityGroup && this.hasOpenIngress(securityGroup)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Remove open ingress rules (0.0.0.0/0) from security group '${sgId}' and restrict access to specific IP ranges.`
        );
      }
    }

    // No open ingress found - EMR7 requirement satisfied
    return null;
  }

  private hasOpenIngress(securityGroup: CloudFormationResource): boolean {
    const securityGroupIngress = securityGroup.Properties?.SecurityGroupIngress;
    
    if (!Array.isArray(securityGroupIngress)) {
      return false;
    }

    return securityGroupIngress.some((rule: any) => 
      rule.CidrIp === '0.0.0.0/0' || 
      (Array.isArray(rule.CidrIpv6) && rule.CidrIpv6.includes('::/0'))
    );
  }
}

export default new EMR007Rule();