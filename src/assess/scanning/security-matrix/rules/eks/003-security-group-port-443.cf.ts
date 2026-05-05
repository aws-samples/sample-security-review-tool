import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS3 Rule: Ensure that cluster security groups are configured to allow inbound traffic only on port 443.
 * 
 * Documentation: "The security groups associated with a solution cluster(s) should be configured to allow 
 * inbound traffic only on TCP port 443 (HTTPS) in order to protect the cluster(s) against malicious 
 * activities such as brute-force attacks."
 */
export class EKS003Rule extends BaseRule {
  constructor() {
    super(
      'EKS-003',
      'HIGH',
      'EKS cluster security group allows inbound traffic on ports other than 443',
      ['AWS::EKS::Cluster', 'AWS::EC2::SecurityGroup']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // First, handle direct security group resources
    if (resource.Type === 'AWS::EC2::SecurityGroup') {
      // Check if this security group is associated with an EKS cluster
      const isEksSecurityGroup = this.isSecurityGroupAssociatedWithEks(resource, allResources);

      if (isEksSecurityGroup) {
        return this.evaluateSecurityGroup(resource, stackName);
      }
      return null;
    }

    // Then, handle EKS cluster resources with security group references
    if (resource.Type === 'AWS::EKS::Cluster') {
      const resourcesVpcConfig = resource.Properties?.ResourcesVpcConfig;
      if (!resourcesVpcConfig) {
        return null;
      }

      const securityGroupIds = resourcesVpcConfig.SecurityGroupIds;
      if (!securityGroupIds) {
        return null;
      }

      // Handle CloudFormation intrinsic functions for SecurityGroupIds
      if (typeof securityGroupIds === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set SecurityGroupIds to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }

      // If we have allResources, we can check the referenced security groups
      if (allResources && Array.isArray(allResources)) {
        for (const sgId of securityGroupIds) {
          // Handle both direct IDs and Ref intrinsic functions
          if (typeof sgId === 'object') {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Set SecurityGroupIds to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
            );
          }

          const sgLogicalId = typeof sgId === 'string' ? sgId :
            (sgId.Ref ? sgId.Ref : null);

          if (sgLogicalId) {
            const securityGroup = allResources.find(r =>
              r.Type === 'AWS::EC2::SecurityGroup' && r.LogicalId === sgLogicalId);

            if (securityGroup) {
              const result = this.evaluateSecurityGroup(securityGroup, stackName);
              if (result) {
                return result;
              }
            }
          }
        }
      }
    }

    return null;
  }

  private evaluateSecurityGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const securityGroupIngress = resource.Properties?.SecurityGroupIngress;

    if (!securityGroupIngress || !Array.isArray(securityGroupIngress)) {
      return null;
    }

    for (const ingressRule of securityGroupIngress) {
      // Skip if this is an egress rule
      if (ingressRule.Direction === 'egress') {
        continue;
      }

      // Check for CloudFormation intrinsic functions in ingress rule
      if (typeof ingressRule === 'object') {
        const fromPort = ingressRule.FromPort;
        const toPort = ingressRule.ToPort;

        if (typeof fromPort === 'object' || typeof toPort === 'object') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Set port ranges to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
          );
        }
      }

      // Check if the rule allows traffic on ports other than 443
      const fromPort = ingressRule.FromPort;
      const toPort = ingressRule.ToPort;
      const ipProtocol = ingressRule.IpProtocol;

      // Skip if it's not TCP
      if (ipProtocol !== 'tcp' && ipProtocol !== '6') {
        continue;
      }

      // If port range includes anything other than 443
      if (fromPort !== 443 || toPort !== 443) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (allows traffic on port range ${fromPort}-${toPort})`,
          `Restrict inbound traffic to only TCP port 443 for HTTPS.`
        );
      }
    }

    return null;
  }

  private isSecurityGroupAssociatedWithEks(securityGroup: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    // Check if any EKS cluster references this security group
    const securityGroupLogicalId = securityGroup.LogicalId;

    for (const resource of allResources) {
      if (resource.Type === 'AWS::EKS::Cluster') {
        const resourcesVpcConfig = resource.Properties?.ResourcesVpcConfig;
        if (!resourcesVpcConfig || !resourcesVpcConfig.SecurityGroupIds) {
          continue;
        }

        const securityGroupIds = resourcesVpcConfig.SecurityGroupIds;
        if (Array.isArray(securityGroupIds)) {
          for (const sgId of securityGroupIds) {
            // Handle both direct IDs and Ref intrinsic functions
            const sgLogicalId = typeof sgId === 'string' ? sgId :
              (sgId.Ref ? sgId.Ref : null);

            if (sgLogicalId === securityGroupLogicalId) {
              return true;
            }
          }
        }
      }
    }

    // Check if security group has tags indicating it's for EKS
    const tags = securityGroup.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      for (const tag of tags) {
        if (
          (tag.Key === 'aws:eks:cluster-name' ||
            tag.Key === 'kubernetes.io/cluster/') ||
          (tag.Key === 'Name' && typeof tag.Value === 'string' &&
            (tag.Value.includes('eks') || tag.Value.includes('kubernetes')))
        ) {
          return true;
        }
      }
    }

    return false;
  }
}

export default new EKS003Rule();
