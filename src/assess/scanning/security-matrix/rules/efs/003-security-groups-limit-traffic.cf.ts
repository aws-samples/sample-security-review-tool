import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * EFS3 Rule: Ensure security groups limit traffic to the minimum IP ranges for EC2 instances and other NFS clients.
 * 
 * Documentation: "Many NFS clients and servers use IP addresses as a primary security control. EFS requires IP-based
 * restrictions on network traffic."
 * 
 * Note: Basic security group checks are covered by Checkov rules:
 * - CKV_AWS_260: Ensure EFS is not publicly accessible
 */
export class EFS003Rule extends BaseRule {
  constructor() {
    super(
      'EFS-003',
      'HIGH',
      'EFS security groups allow traffic from overly permissive IP ranges',
      [
        'AWS::EFS::FileSystem',
        'AWS::EFS::MountTarget',
        'AWS::EC2::SecurityGroup',
        'AWS::EC2::SecurityGroupIngress'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Skip if we don't have allResources - we need context to evaluate properly
    if (!allResources || !Array.isArray(allResources)) {
      return null;
    }

    const resolver = new CloudFormationResolver(allResources);

    // For EFS FileSystem resources, we need to check if they have associated mount targets
    if (resource.Type === 'AWS::EFS::FileSystem') {
      // The actual security group check will be done on the MountTarget resources
      return null;
    }

    // Find all EFS mount targets and their security groups
    const mountTargets = allResources.filter(res => res.Type === 'AWS::EFS::MountTarget');
    const efsSecurityGroupIds = new Set<string>();

    // Collect all security group references from mount targets
    for (const mt of mountTargets) {
      const securityGroups = mt.Properties?.SecurityGroups;
      if (securityGroups) {
        const resolved = resolver.resolve(securityGroups, {
          treatLiteralStringsAs: 'external-references'
        });

        // If we have resolved security groups, add them to our set
        if (resolved.isResolved && Array.isArray(resolved.value)) {
          resolved.value.forEach(sgId => efsSecurityGroupIds.add(sgId));
        }

        // Also track referenced resources that might be security groups
        resolved.referencedResources.forEach(sgId => efsSecurityGroupIds.add(sgId));
      }
    }

    // For EFS MountTarget resources, we need to check the associated security groups
    if (resource.Type === 'AWS::EFS::MountTarget') {
      const securityGroups = resource.Properties?.SecurityGroups;

      if (!securityGroups) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify security groups for the EFS mount target that restrict access to specific IP ranges.`
        );
      }

      // Resolve security groups
      const resolved = resolver.resolve(securityGroups, {
        treatLiteralStringsAs: 'external-references'
      });

      if (!resolved.isResolved && resolved.referencedResources.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify security groups for the EFS mount target that restrict access to specific IP ranges.`
        );
      }

      // Check referenced security groups
      for (const sgId of resolved.referencedResources) {
        const sg = resolver.getResource(sgId);
        if (sg?.Type === 'AWS::EC2::SecurityGroup') {
          const result = this.evaluateSecurityGroup(sg, stackName);
          if (result) return result;
        }
      }

      // Check for standalone ingress rules that might target these security groups
      const standaloneIngressRules = allResources.filter(res =>
        res.Type === 'AWS::EC2::SecurityGroupIngress'
      );

      for (const sgId of resolved.referencedResources) {
        for (const rule of standaloneIngressRules) {
          const groupId = resolver.resolve(rule.Properties?.GroupId);
          const groupName = resolver.resolve(rule.Properties?.GroupName);

          if ((groupId.referencedResources.includes(sgId) || groupId.value === sgId) ||
            (groupName.referencedResources.includes(sgId) || groupName.value === sgId)) {
            const result = this.evaluateStandaloneIngress(rule, stackName);
            if (result) return result;
          }
        }
      }
    }

    // For SecurityGroup resources, check if they're used by EFS mount targets
    if (resource.Type === 'AWS::EC2::SecurityGroup') {
      // Skip if this security group is not referenced by any EFS mount target
      if (!efsSecurityGroupIds.has(resource.LogicalId)) {
        return null;
      }

      // We'll check this security group if it has ingress rules for NFS (port 2049)
      let ingressRules = resource.Properties?.SecurityGroupIngress;

      // Normalize to array if it's a single object
      if (ingressRules && !Array.isArray(ingressRules)) {
        ingressRules = [ingressRules];
      }

      if (ingressRules && Array.isArray(ingressRules)) {
        // Check for NFS port (2049) in any ingress rule
        const hasNfsPort = ingressRules.some(rule => this.isNfsPortRule(rule));

        if (hasNfsPort) {
          return this.evaluateSecurityGroup(resource, stackName);
        }
      }
    }

    // For standalone SecurityGroupIngress resources
    if (resource.Type === 'AWS::EC2::SecurityGroupIngress') {
      // Check if this ingress rule targets a security group used by an EFS mount target
      const groupId = resource.Properties?.GroupId;
      const groupName = resource.Properties?.GroupName;

      let isEfsSecurityGroup = false;

      // Check GroupId
      if (groupId) {
        const resolvedGroupId = resolver.resolve(groupId);

        // Check if it references a security group used by EFS
        if (resolvedGroupId.isResolved && efsSecurityGroupIds.has(resolvedGroupId.value)) {
          isEfsSecurityGroup = true;
        }

        // Check referenced resources
        for (const refId of resolvedGroupId.referencedResources) {
          if (efsSecurityGroupIds.has(refId)) {
            isEfsSecurityGroup = true;
            break;
          }
        }
      }

      // Check GroupName if GroupId didn't match
      if (!isEfsSecurityGroup && groupName) {
        const resolvedGroupName = resolver.resolve(groupName);

        // Check if it references a security group used by EFS
        if (resolvedGroupName.isResolved && efsSecurityGroupIds.has(resolvedGroupName.value)) {
          isEfsSecurityGroup = true;
        }

        // Check referenced resources
        for (const refId of resolvedGroupName.referencedResources) {
          if (efsSecurityGroupIds.has(refId)) {
            isEfsSecurityGroup = true;
            break;
          }
        }
      }

      // Skip if this ingress rule doesn't target an EFS security group
      if (!isEfsSecurityGroup) {
        return null;
      }

      // Check if this is an NFS port rule
      if (this.isNfsPortRule(resource.Properties)) {
        return this.evaluateStandaloneIngress(resource, stackName);
      }
    }

    return null;
  }


  private evaluateSecurityGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure security group ingress rules to restrict NFS traffic to specific IP ranges.`
      );
    }

    const resolver = new CloudFormationResolver();

    let ingressRules = resource.Properties.SecurityGroupIngress;

    // Normalize to array if it's a single object
    if (ingressRules && !Array.isArray(ingressRules)) {
      ingressRules = [ingressRules];
    }

    if (!ingressRules || !Array.isArray(ingressRules) || ingressRules.length === 0) {
      return null; // No ingress rules to check
    }

    for (const rule of ingressRules) {
      // Check if the rule uses TCP protocol (NFS requires TCP)
      const isTcpProtocol = this.isTcpProtocol(rule.IpProtocol);
      if (!isTcpProtocol) {
        continue;
      }

      // Check if this is an NFS port rule
      if (!this.isNfsPortRule(rule)) {
        continue;
      }

      // Skip security group-to-security group rules for wide range check
      const isSecurityGroupRule = rule.SourceSecurityGroupId !== undefined ||
        rule.SourceSecurityGroupName !== undefined;

      // Check for intrinsic functions in CidrIp using resolver
      if (rule.CidrIp) {
        const resolvedCidrIp = resolver.resolve(rule.CidrIp);
        if (!resolvedCidrIp.isResolved) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use explicit CIDR ranges rather than CloudFormation functions that cannot be validated at scan time.`
          );
        }
        rule.CidrIp = resolvedCidrIp.value;
      }

      // Check for intrinsic functions in CidrIpv6 using resolver
      if (rule.CidrIpv6) {
        const resolvedCidrIpv6 = resolver.resolve(rule.CidrIpv6);
        if (!resolvedCidrIpv6.isResolved) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use explicit IPv6 CIDR ranges rather than CloudFormation functions that cannot be validated at scan time.`
          );
        }
        rule.CidrIpv6 = resolvedCidrIpv6.value;
      }

      // Check for overly permissive CIDR ranges
      if (rule.CidrIp === '0.0.0.0/0') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Restrict NFS traffic (port 2049) to specific IP ranges instead of ${rule.CidrIp}.`
        );
      }

      // Check for overly permissive IPv6 CIDR ranges
      if (rule.CidrIpv6 === '::/0') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Restrict NFS traffic (port 2049) to specific IPv6 ranges instead of ${rule.CidrIpv6}.`
        );
      }

      // Check for wide CIDR ranges (less than /16 for IPv4), but skip for security group-to-security group rules
      if (!isSecurityGroupRule && rule.CidrIp && typeof rule.CidrIp === 'string') {
        const cidrParts = rule.CidrIp.split('/');
        if (cidrParts.length === 2) {
          const prefix = parseInt(cidrParts[1], 10);
          if (!isNaN(prefix) && prefix < 16) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Use a more restrictive CIDR range than ${rule.CidrIp} for NFS traffic.`
            );
          }
        }
      }
    }

    return null;
  }

  private evaluateStandaloneIngress(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const rule = resource.Properties;

    if (!rule) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure security group ingress rules to restrict NFS traffic to specific IP ranges.`
      );
    }

    const resolver = new CloudFormationResolver();

    // Check if the rule uses TCP protocol (NFS requires TCP)
    const isTcpProtocol = this.isTcpProtocol(rule.IpProtocol);
    if (!isTcpProtocol) {
      return null;
    }

    // Check if this is an NFS port rule
    if (!this.isNfsPortRule(rule)) {
      return null;
    }

    // Skip security group-to-security group rules for wide range check
    const isSecurityGroupRule = rule.SourceSecurityGroupId !== undefined ||
      rule.SourceSecurityGroupName !== undefined;

    // Check for intrinsic functions in CidrIp using resolver
    if (rule.CidrIp) {
      const resolvedCidrIp = resolver.resolve(rule.CidrIp);
      if (!resolvedCidrIp.isResolved) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use explicit CIDR ranges rather than CloudFormation functions that cannot be validated at scan time.`
        );
      }
      rule.CidrIp = resolvedCidrIp.value;
    }

    // Check for intrinsic functions in CidrIpv6 using resolver
    if (rule.CidrIpv6) {
      const resolvedCidrIpv6 = resolver.resolve(rule.CidrIpv6);
      if (!resolvedCidrIpv6.isResolved) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Use explicit IPv6 CIDR ranges rather than CloudFormation functions that cannot be validated at scan time.`
        );
      }
      rule.CidrIpv6 = resolvedCidrIpv6.value;
    }

    // Check for overly permissive CIDR ranges
    if (rule.CidrIp === '0.0.0.0/0') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Restrict NFS traffic (port 2049) to specific IP ranges instead of ${rule.CidrIp}.`
      );
    }

    // Check for overly permissive IPv6 CIDR ranges
    if (rule.CidrIpv6 === '::/0') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Restrict NFS traffic (port 2049) to specific IPv6 ranges instead of ${rule.CidrIpv6}.`
      );
    }

    // Check for wide CIDR ranges (less than /16 for IPv4), but skip for security group-to-security group rules
    if (!isSecurityGroupRule && rule.CidrIp && typeof rule.CidrIp === 'string') {
      const cidrParts = rule.CidrIp.split('/');
      if (cidrParts.length === 2) {
        const prefix = parseInt(cidrParts[1], 10);
        if (!isNaN(prefix) && prefix < 16) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use a more restrictive CIDR range than ${rule.CidrIp} for NFS traffic.`
          );
        }
      }
    }

    return null;
  }

  /**
   * Checks if a rule is for NFS port (2049)
   * @param rule The rule to check
   * @returns True if the rule is for NFS port, false otherwise
   */
  private isNfsPortRule(rule: any): boolean {
    if (!rule) {
      return false;
    }

    const resolver = new CloudFormationResolver();

    // Check for intrinsic functions in FromPort/ToPort using resolver
    if (rule.FromPort) {
      const resolvedFromPort = resolver.resolve(rule.FromPort);
      if (!resolvedFromPort.isResolved) {
        // If we can't determine the port range due to intrinsic functions,
        // we'll be conservative and assume it might include NFS port
        return true;
      }
      rule.FromPort = resolvedFromPort.value;
    }

    if (rule.ToPort) {
      const resolvedToPort = resolver.resolve(rule.ToPort);
      if (!resolvedToPort.isResolved) {
        // If we can't determine the port range due to intrinsic functions,
        // we'll be conservative and assume it might include NFS port
        return true;
      }
      rule.ToPort = resolvedToPort.value;
    }

    // Check for NFS port (2049), guarding against undefined FromPort/ToPort
    // Coerce port values to numbers to handle string values in CloudFormation templates
    let fromPort: number | undefined;
    let toPort: number | undefined;

    // Handle all protocols case
    if (rule.IpProtocol === '-1' || rule.IpProtocol === -1) {
      fromPort = 0;
      toPort = 65535;
    } else {
      // Coerce FromPort to number if defined
      if (rule.FromPort !== undefined) {
        fromPort = typeof rule.FromPort === 'string' ? parseInt(rule.FromPort, 10) : Number(rule.FromPort);
        if (isNaN(fromPort)) {
          return false; // Skip if we can't parse the port
        }
      }

      // Coerce ToPort to number if defined
      if (rule.ToPort !== undefined) {
        toPort = typeof rule.ToPort === 'string' ? parseInt(rule.ToPort, 10) : Number(rule.ToPort);
        if (isNaN(toPort)) {
          return false; // Skip if we can't parse the port
        }
      }

      // Handle single-port rules (only FromPort or only ToPort)
      if (fromPort === undefined && toPort !== undefined) {
        // Only ToPort is defined
        return toPort === 2049;
      }

      if (toPort === undefined && fromPort !== undefined) {
        // Only FromPort is defined
        return fromPort === 2049;
      }
    }

    // Skip if we can't determine port range at all
    if (fromPort === undefined && toPort === undefined) {
      return false;
    }

    // Check if the port range includes NFS port (2049)
    return fromPort === 2049 || toPort === 2049 ||
      (fromPort !== undefined && toPort !== undefined && fromPort <= 2049 && toPort >= 2049);
  }

  /**
   * Checks if the protocol is TCP
   * @param protocol The protocol to check
   * @returns True if the protocol is TCP, false otherwise
   */
  private isTcpProtocol(protocol: any): boolean {
    if (protocol === undefined) {
      // Default protocol is TCP if not specified
      return true;
    }

    const resolver = new CloudFormationResolver();

    // Check for intrinsic functions in protocol using resolver
    if (protocol && typeof protocol === 'object') {
      const resolvedProtocol = resolver.resolve(protocol);
      if (!resolvedProtocol.isResolved) {
        // If we can't determine the protocol due to intrinsic functions,
        // we'll be conservative and assume it might be TCP
        return true;
      }
      protocol = resolvedProtocol.value;
    }

    // Handle numeric values
    if (typeof protocol === 'number') {
      return protocol === 6 || protocol === -1;
    }

    if (typeof protocol === 'string') {
      // Handle numeric strings
      if (protocol === '6' || protocol === '-1') {
        return true;
      }

      // Handle text strings
      const protocolLower = protocol.toLowerCase();
      return protocolLower === 'tcp';
    }

    return false;
  }
}

export default new EFS003Rule();
