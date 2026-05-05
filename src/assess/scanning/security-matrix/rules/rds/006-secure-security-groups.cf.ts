import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { isPublicCidr } from '../../../utils/cloudformation-intrinsic-utils.js';
import { hasRelationshipWithResourceTypes } from '../../../utils/resource-relationship-utils.js';

export class Rds006Rule extends BaseRule {
  constructor() {
    super(
      'RDS-006',
      'HIGH',
      'RDS security group allows access from 0.0.0.0/0',
      ['AWS::EC2::SecurityGroup', 'AWS::EC2::SecurityGroupIngress']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if we don't have all resources (needed to check relationships)
    if (!allResources) {
      return null;
    }

    // Check if this is a security group
    if (resource.Type === 'AWS::EC2::SecurityGroup') {
      // Check if this security group is associated with an RDS resource
      const isRdsSecurityGroup = this.isSecurityGroupAssociatedWithRds(resource, allResources);

      if (isRdsSecurityGroup) {
        // Check ingress rules for public access
        const securityGroupIngress = resource.Properties?.SecurityGroupIngress;

        if (securityGroupIngress && Array.isArray(securityGroupIngress)) {
          for (const ingress of securityGroupIngress) {
            const cidrIp = ingress.CidrIp;
            const cidrIpv6 = ingress.CidrIpv6;

            // Check if this is a public CIDR
            if (isPublicCidr(cidrIp) || isPublicCidr(cidrIpv6)) {
              const port = this.getPortDescription(ingress.FromPort, ingress.ToPort);
              return this.createScanResult(
                resource,
                stackName,
                `${this.description} on port ${port}`,
                `Restrict the CidrIp to specific IP ranges that need access.`
              );
            }
          }
        }
      }
    }

    // Check if this is a security group ingress rule
    if (resource.Type === 'AWS::EC2::SecurityGroupIngress') {
      const groupId = resource.Properties?.GroupId;

      if (groupId) {
        // Find the security group this ingress rule applies to
        const securityGroup = allResources.find(res =>
          res.Type === 'AWS::EC2::SecurityGroup' &&
          res.LogicalId === groupId
        );

        // Check if the security group is associated with an RDS resource
        if (securityGroup && this.isSecurityGroupAssociatedWithRds(securityGroup, allResources)) {
          const cidrIp = resource.Properties?.CidrIp;
          const cidrIpv6 = resource.Properties?.CidrIpv6;

          // Check if this is a public CIDR
          if (isPublicCidr(cidrIp) || isPublicCidr(cidrIpv6)) {
            const port = this.getPortDescription(resource.Properties?.FromPort, resource.Properties?.ToPort);
            return this.createScanResult(
              resource,
              stackName,
              `${this.description} on port ${port}`,
              `Restrict the CidrIp to specific IP ranges that need access.`
            );
          }
        }
      }
    }

    return null;
  }

  /**
   * Checks if a security group is associated with any RDS resources
   * @param resource The security group resource
   * @param allResources All resources in the template
   * @returns True if the security group is associated with an RDS resource, false otherwise
   */
  private isSecurityGroupAssociatedWithRds(resource: CloudFormationResource, allResources: CloudFormationResource[]): boolean {
    if (resource.Type !== 'AWS::EC2::SecurityGroup') {
      return false;
    }

    // Find all RDS resources
    const rdsResources = allResources.filter(res =>
      res.Type === 'AWS::RDS::DBInstance' ||
      res.Type === 'AWS::RDS::DBCluster'
    );

    // Check if any RDS resource references this security group
    for (const rdsResource of rdsResources) {
      // Check VPCSecurityGroups property for references to this security group
      const vpcSecurityGroups = rdsResource.Properties?.VPCSecurityGroups;

      if (vpcSecurityGroups && Array.isArray(vpcSecurityGroups)) {
        // Convert to string to check for any kind of reference
        const securityGroupsStr = JSON.stringify(vpcSecurityGroups);

        // Check if the security group ID is referenced
        if (securityGroupsStr.includes(resource.LogicalId)) {
          return true;
        }

        // Check for GetAtt references (which might include GroupId)
        if (securityGroupsStr.includes(`${resource.LogicalId}.GroupId`)) {
          return true;
        }
      }
    }

    // Check if this security group is directly referenced by an RDS resource
    const isDirectlyReferenced = hasRelationshipWithResourceTypes(
      resource,
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
      allResources
    );

    if (isDirectlyReferenced) {
      return true;
    }

    // Check if this security group is referenced by a DB subnet group that's used by an RDS resource
    const dbSubnetGroups = allResources.filter(res => res.Type === 'AWS::RDS::DBSubnetGroup');

    for (const subnetGroup of dbSubnetGroups) {
      // Check if the subnet group references this security group
      const referencesSecurityGroup = hasRelationshipWithResourceTypes(
        subnetGroup,
        ['AWS::EC2::SecurityGroup'],
        [resource]
      );

      if (referencesSecurityGroup) {
        // Check if any RDS resource references this subnet group
        const rdsResources = allResources.filter(res =>
          res.Type === 'AWS::RDS::DBInstance' || res.Type === 'AWS::RDS::DBCluster'
        );

        for (const rdsResource of rdsResources) {
          const referencesSubnetGroup = hasRelationshipWithResourceTypes(
            rdsResource,
            ['AWS::RDS::DBSubnetGroup'],
            [subnetGroup]
          );

          if (referencesSubnetGroup) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Gets a description of the port range
   */
  private getPortDescription(fromPort: any, toPort: any): string {
    if (fromPort === undefined || toPort === undefined) {
      return "all ports";
    }

    if (fromPort === toPort) {
      return `${fromPort}`;
    } else {
      return `${fromPort}-${toPort}`;
    }
  }
}

export default new Rds006Rule();
