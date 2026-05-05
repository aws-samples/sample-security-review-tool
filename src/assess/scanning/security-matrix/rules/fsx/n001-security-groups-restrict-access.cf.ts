import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';
import { isReferenceToResource, extractResourceIdsFromReference } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * FSxN1 Rule: Do the file-system security groups for both the preferred and standby subnet endpoints restrict SSH and API (HTTP) access to appropriate sources?
 * 
 * Documentation: "FSxN allows SSH access to file system and SVMs. This access should be restricted to specific sources (perhaps a bastion host)."
 */
export class FSxN001Rule extends BaseRule {
  constructor() {
    super(
      'FSxN-001',
      'HIGH',
      'File system security groups allow SSH or API access from overly permissive sources',
      [
        'AWS::FSx::FileSystem',
        'AWS::EC2::SecurityGroup',
        'AWS::EC2::SecurityGroupIngress'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    // Skip if we don't have allResources - we need context to evaluate properly
    if (!allResources || !Array.isArray(allResources)) {
      return null;
    }

    const resolver = new CloudFormationResolver(allResources);

    // For FSx FileSystem resources
    if (resource.Type === 'AWS::FSx::FileSystem') {
      const fileSystemType = resource.Properties?.FileSystemType;

      // This rule is primarily for ONTAP (FSxN) file systems
      const resolvedFileSystemType = resolver.resolve(fileSystemType);
      if (!resolvedFileSystemType.isResolved || resolvedFileSystemType.value !== 'ONTAP') {
        return null;
      }

      const ontapConfiguration = resource.Properties?.OntapConfiguration;

      if (!ontapConfiguration) {
        return null;
      }

      // Get the security groups associated with this file system
      const preferredSubnetId = ontapConfiguration.PreferredSubnetId;
      const endpointIpAddressRange = ontapConfiguration.EndpointIpAddressRange;

      // If we can't determine the subnet or endpoint IP range, we can't evaluate security
      if (!preferredSubnetId) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify PreferredSubnetId for the ONTAP file system.`
        );
      }

      // Check if there are security groups associated with this file system
      const securityGroups = this.findAssociatedSecurityGroups(resource, allResources, resolver);

      // If security groups are specified but not found in resources, return null
      const securityGroupIds = ontapConfiguration.SecurityGroupIds;
      if (securityGroupIds && Array.isArray(securityGroupIds) && securityGroupIds.length > 0 && securityGroups.length === 0) {
        return null;
      }

      if (securityGroups.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Associate security groups with the ONTAP file system to restrict SSH and API access.`
        );
      }

      // Check each security group for SSH and API access rules
      for (const sg of securityGroups) {
        const result = this.evaluateSecurityGroup(sg, stackName, resolver);
        if (result) {
          return result;
        }
      }
    }

    // For SecurityGroup resources
    if (resource.Type === 'AWS::EC2::SecurityGroup') {
      // Check if this security group is associated with any FSx ONTAP file systems
      const isAssociatedWithFsxN = this.isSecurityGroupAssociatedWithFsxN(resource, allResources, resolver);

      if (isAssociatedWithFsxN) {
        return this.evaluateSecurityGroup(resource, stackName, resolver);
      }
    }

    // For standalone SecurityGroupIngress resources
    if (resource.Type === 'AWS::EC2::SecurityGroupIngress') {
      // Check if this ingress rule targets a security group used by an FSx ONTAP file system
      const targetsSgForFsxN = this.ingressTargetsFsxNSecurityGroup(resource, allResources, resolver);

      if (targetsSgForFsxN) {
        return this.evaluateSecurityGroupIngress(resource, stackName, resolver);
      }
    }

    return null;
  }

  /**
   * Finds security groups associated with an FSx ONTAP file system
   * @param fsxResource The FSx file system resource
   * @param allResources All resources in the template
   * @returns Array of security group resources associated with the file system
   */
  private findAssociatedSecurityGroups(fsxResource: CloudFormationResource, allResources: CloudFormationResource[], resolver: CloudFormationResolver): CloudFormationResource[] {
    const associatedSgs: CloudFormationResource[] = [];
    const ontapConfiguration = fsxResource.Properties?.OntapConfiguration;

    if (!ontapConfiguration) {
      return associatedSgs;
    }

    // Get the security group IDs from the file system
    const securityGroupIds = ontapConfiguration.SecurityGroupIds;

    if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
      return associatedSgs;
    }

    // Find the security group resources
    for (const sgId of securityGroupIds) {
      for (const resource of allResources) {
        if (resource.Type !== 'AWS::EC2::SecurityGroup') {
          continue;
        }

        // Direct match
        if (resource.LogicalId === sgId) {
          associatedSgs.push(resource);
          continue;
        }

        // Check for intrinsic function references
        if (isReferenceToResource(sgId, resource.LogicalId)) {
          associatedSgs.push(resource);
          continue;
        }

        // Extract resource IDs from references
        const resourceIds = extractResourceIdsFromReference(sgId);
        if (resourceIds.includes(resource.LogicalId)) {
          associatedSgs.push(resource);
        }
      }
    }

    return associatedSgs;
  }

  /**
   * Checks if a security group is associated with any FSx ONTAP file systems
   * @param sgResource The security group resource
   * @param allResources All resources in the template
   * @param resolver CloudFormation resolver for handling intrinsic functions
   * @returns True if the security group is associated with an FSx ONTAP file system, false otherwise
   */
  private isSecurityGroupAssociatedWithFsxN(sgResource: CloudFormationResource, allResources: CloudFormationResource[], resolver: CloudFormationResolver): boolean {
    // Find all FSx file systems
    const fsxSystems = allResources.filter(res => res.Type === 'AWS::FSx::FileSystem');

    // Check if any of them are ONTAP systems and reference this security group
    for (const fsxSystem of fsxSystems) {
      const fileSystemType = fsxSystem.Properties?.FileSystemType;

      // Resolve the file system type
      const resolvedFileSystemType = resolver.resolve(fileSystemType);
      if (!resolvedFileSystemType.isResolved || resolvedFileSystemType.value !== 'ONTAP') {
        continue;
      }

      const ontapConfiguration = fsxSystem.Properties?.OntapConfiguration;

      if (!ontapConfiguration) {
        continue;
      }

      const securityGroupIds = ontapConfiguration.SecurityGroupIds;

      if (!securityGroupIds || !Array.isArray(securityGroupIds)) {
        continue;
      }

      for (const sgId of securityGroupIds) {
        // Resolve the security group ID
        const resolvedSgId = resolver.resolve(sgId);

        // If we can't resolve it, we need to be conservative
        if (!resolvedSgId.isResolved) {
          // Check if the unresolved reference might point to our security group
          if (isReferenceToResource(sgId, sgResource.LogicalId)) {
            return true;
          }

          // Extract resource IDs from references
          const resourceIds = extractResourceIdsFromReference(sgId);
          if (resourceIds.includes(sgResource.LogicalId)) {
            return true;
          }

          continue;
        }

        // Direct match with resolved value
        if (resolvedSgId.value === sgResource.LogicalId) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Checks if a security group ingress rule targets a security group used by an FSx ONTAP file system
   * @param ingressResource The security group ingress resource
   * @param allResources All resources in the template
   * @param resolver CloudFormation resolver for handling intrinsic functions
   * @returns True if the ingress rule targets a security group used by an FSx ONTAP file system, false otherwise
   */
  private ingressTargetsFsxNSecurityGroup(ingressResource: CloudFormationResource, allResources: CloudFormationResource[], resolver: CloudFormationResolver): boolean {
    const groupId = ingressResource.Properties?.GroupId;
    const groupName = ingressResource.Properties?.GroupName;

    if (!groupId && !groupName) {
      return false;
    }

    // Find all FSx file systems
    const fsxSystems = allResources.filter(res => res.Type === 'AWS::FSx::FileSystem');

    const fsxSecurityGroupIds = new Set<string>();

    // Find all security groups associated with FSx ONTAP file systems
    for (const fsxSystem of fsxSystems) {
      const fileSystemType = fsxSystem.Properties?.FileSystemType;

      // Resolve the file system type
      const resolvedFileSystemType = resolver.resolve(fileSystemType);
      if (!resolvedFileSystemType.isResolved || resolvedFileSystemType.value !== 'ONTAP') {
        continue;
      }

      const ontapConfiguration = fsxSystem.Properties?.OntapConfiguration;

      if (!ontapConfiguration) {
        continue;
      }

      const securityGroupIds = ontapConfiguration.SecurityGroupIds;

      if (!securityGroupIds || !Array.isArray(securityGroupIds)) {
        continue;
      }

      for (const sgId of securityGroupIds) {
        // Resolve the security group ID
        const resolvedSgId = resolver.resolve(sgId);

        if (resolvedSgId.isResolved) {
          fsxSecurityGroupIds.add(resolvedSgId.value);
        } else {
          // If we can't resolve it, add the raw value for reference checking
          if (typeof sgId === 'string') {
            fsxSecurityGroupIds.add(sgId);
          }

          // Extract resource IDs from references
          const resourceIds = extractResourceIdsFromReference(sgId);
          for (const id of resourceIds) {
            fsxSecurityGroupIds.add(id);
          }
        }
      }
    }

    // Check if the ingress rule targets any of these security groups
    if (groupId) {
      // Resolve the group ID
      const resolvedGroupId = resolver.resolve(groupId);

      if (resolvedGroupId.isResolved) {
        // Direct match with resolved value
        if (fsxSecurityGroupIds.has(resolvedGroupId.value)) {
          return true;
        }
      } else {
        // Direct match with unresolved value
        if (fsxSecurityGroupIds.has(groupId)) {
          return true;
        }

        // Check for intrinsic function references
        for (const sgId of fsxSecurityGroupIds) {
          if (isReferenceToResource(groupId, sgId)) {
            return true;
          }
        }
      }
    }

    if (groupName) {
      // Resolve the group name
      const resolvedGroupName = resolver.resolve(groupName);

      // Find security groups by name
      const securityGroups = allResources.filter(res =>
        res.Type === 'AWS::EC2::SecurityGroup' &&
        fsxSecurityGroupIds.has(res.LogicalId)
      );

      for (const sg of securityGroups) {
        const sgName = sg.Properties?.GroupName;

        // Resolve the security group name
        const resolvedSgName = resolver.resolve(sgName);

        if (resolvedSgName.isResolved && resolvedGroupName.isResolved) {
          // Direct match with resolved values
          if (resolvedSgName.value === resolvedGroupName.value) {
            return true;
          }
        } else {
          // Direct match with unresolved values
          if (sgName === groupName) {
            return true;
          }

          // Check for intrinsic function references
          if (isReferenceToResource(groupName, sgName)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Evaluates a security group for SSH and API access rules
   * @param resource The security group resource
   * @param stackName The stack name
   * @returns A scan result if the security group allows overly permissive SSH or API access, null otherwise
   */
  private evaluateSecurityGroup(resource: CloudFormationResource, stackName: string, resolver?: CloudFormationResolver): ScanResult | null {
    if (!resolver) {
      resolver = new CloudFormationResolver([resource]);
    }

    let ingressRules = resource.Properties?.SecurityGroupIngress;

    // Normalize to array if it's a single object
    if (ingressRules && !Array.isArray(ingressRules)) {
      ingressRules = [ingressRules];
    }

    if (!ingressRules || !Array.isArray(ingressRules) || ingressRules.length === 0) {
      return null; // No ingress rules to check
    }

    for (const rule of ingressRules) {
      // Check for SSH access (port 22)
      if (this.isSshPort(rule)) {
        const result = this.checkForOverlyPermissiveAccess(rule, 'SSH', resource, stackName, resolver);
        if (result) {
          return result;
        }
      }

      // Check for HTTP/HTTPS API access (ports 80, 443, 8080)
      if (this.isApiPort(rule)) {
        const result = this.checkForOverlyPermissiveAccess(rule, 'API', resource, stackName, resolver);
        if (result) {
          return result;
        }
      }
    }

    return null;
  }

  /**
   * Evaluates a standalone security group ingress rule for SSH and API access
   * @param resource The security group ingress resource
   * @param stackName The stack name
   * @returns A scan result if the ingress rule allows overly permissive SSH or API access, null otherwise
   */
  private evaluateSecurityGroupIngress(resource: CloudFormationResource, stackName: string, resolver?: CloudFormationResolver): ScanResult | null {
    if (!resolver) {
      resolver = new CloudFormationResolver([resource]);
    }

    const rule = resource.Properties;

    if (!rule) {
      return null;
    }

    // Check for SSH access (port 22)
    if (this.isSshPort(rule)) {
      return this.checkForOverlyPermissiveAccess(rule, 'SSH', resource, stackName, resolver);
    }

    // Check for HTTP/HTTPS API access (ports 80, 443, 8080)
    if (this.isApiPort(rule)) {
      return this.checkForOverlyPermissiveAccess(rule, 'API', resource, stackName, resolver);
    }

    return null;
  }

  /**
   * Checks if a rule is for SSH port (22)
   * @param rule The rule to check
   * @returns True if the rule is for SSH port, false otherwise
   */
  private isSshPort(rule: any): boolean {
    if (!rule) {
      return false;
    }

    // Create a resolver for this rule if needed
    const resolver = new CloudFormationResolver([]);

    // Check for SSH port (22), guarding against undefined FromPort/ToPort
    // Coerce port values to numbers to handle string values in CloudFormation templates
    let fromPort: number | undefined;
    let toPort: number | undefined;

    // Handle all protocols case
    const ipProtocol = resolver.resolve(rule.IpProtocol);
    if (ipProtocol.isResolved && (ipProtocol.value === '-1' || ipProtocol.value === -1)) {
      fromPort = 0;
      toPort = 65535;
    } else {
      // Resolve FromPort
      const resolvedFromPort = resolver.resolve(rule.FromPort);
      if (resolvedFromPort.isResolved) {
        fromPort = typeof resolvedFromPort.value === 'string' ?
          parseInt(resolvedFromPort.value, 10) : Number(resolvedFromPort.value);
        if (isNaN(fromPort)) {
          fromPort = undefined; // Skip if we can't parse the port
        }
      } else if (rule.FromPort !== undefined) {
        // If we can't resolve FromPort, be conservative and assume it might include SSH port
        return true;
      }

      // Resolve ToPort
      const resolvedToPort = resolver.resolve(rule.ToPort);
      if (resolvedToPort.isResolved) {
        toPort = typeof resolvedToPort.value === 'string' ?
          parseInt(resolvedToPort.value, 10) : Number(resolvedToPort.value);
        if (isNaN(toPort)) {
          toPort = undefined; // Skip if we can't parse the port
        }
      } else if (rule.ToPort !== undefined) {
        // If we can't resolve ToPort, be conservative and assume it might include SSH port
        return true;
      }

      // Handle single-port rules (only FromPort or only ToPort)
      if (fromPort === undefined && toPort !== undefined) {
        // Only ToPort is defined
        return toPort === 22;
      }

      if (toPort === undefined && fromPort !== undefined) {
        // Only FromPort is defined
        return fromPort === 22;
      }
    }

    // Skip if we can't determine port range at all
    if (fromPort === undefined && toPort === undefined) {
      return false;
    }

    // Check if the port range includes SSH port (22)
    return fromPort === 22 || toPort === 22 ||
      (fromPort !== undefined && toPort !== undefined && fromPort <= 22 && toPort >= 22);
  }

  /**
   * Checks if a rule is for API ports (80, 443, 8080)
   * @param rule The rule to check
   * @returns True if the rule is for API ports, false otherwise
   */
  private isApiPort(rule: any): boolean {
    if (!rule) {
      return false;
    }

    // Create a resolver for this rule if needed
    const resolver = new CloudFormationResolver([]);

    // Check for API ports (80, 443, 8080), guarding against undefined FromPort/ToPort
    // Coerce port values to numbers to handle string values in CloudFormation templates
    let fromPort: number | undefined;
    let toPort: number | undefined;

    // Handle all protocols case
    const ipProtocol = resolver.resolve(rule.IpProtocol);
    if (ipProtocol.isResolved && (ipProtocol.value === '-1' || ipProtocol.value === -1)) {
      fromPort = 0;
      toPort = 65535;
    } else {
      // Resolve FromPort
      const resolvedFromPort = resolver.resolve(rule.FromPort);
      if (resolvedFromPort.isResolved) {
        fromPort = typeof resolvedFromPort.value === 'string' ?
          parseInt(resolvedFromPort.value, 10) : Number(resolvedFromPort.value);
        if (isNaN(fromPort)) {
          fromPort = undefined; // Skip if we can't parse the port
        }
      } else if (rule.FromPort !== undefined) {
        // If we can't resolve FromPort, be conservative and assume it might include API ports
        return true;
      }

      // Resolve ToPort
      const resolvedToPort = resolver.resolve(rule.ToPort);
      if (resolvedToPort.isResolved) {
        toPort = typeof resolvedToPort.value === 'string' ?
          parseInt(resolvedToPort.value, 10) : Number(resolvedToPort.value);
        if (isNaN(toPort)) {
          toPort = undefined; // Skip if we can't parse the port
        }
      } else if (rule.ToPort !== undefined) {
        // If we can't resolve ToPort, be conservative and assume it might include API ports
        return true;
      }

      // Handle single-port rules (only FromPort or only ToPort)
      if (fromPort === undefined && toPort !== undefined) {
        // Only ToPort is defined
        return toPort === 80 || toPort === 443 || toPort === 8080;
      }

      if (toPort === undefined && fromPort !== undefined) {
        // Only FromPort is defined
        return fromPort === 80 || fromPort === 443 || fromPort === 8080;
      }
    }

    // Skip if we can't determine port range at all
    if (fromPort === undefined && toPort === undefined) {
      return false;
    }

    // Check if the port range includes any API ports (80, 443, 8080)
    return (fromPort !== undefined && toPort !== undefined) && (
      // Check for port 80
      (fromPort <= 80 && toPort >= 80) ||
      // Check for port 443
      (fromPort <= 443 && toPort >= 443) ||
      // Check for port 8080
      (fromPort <= 8080 && toPort >= 8080)
    );
  }

  /**
   * Checks if a rule allows overly permissive access
   * @param rule The rule to check
   * @param accessType The type of access (SSH or API)
   * @param resource The resource containing the rule
   * @param stackName The stack name
   * @param resolver CloudFormation resolver for handling intrinsic functions
   * @returns A scan result if the rule allows overly permissive access, null otherwise
   */
  private checkForOverlyPermissiveAccess(rule: any, accessType: string, resource: CloudFormationResource, stackName: string, resolver?: CloudFormationResolver): ScanResult | null {
    if (!resolver) {
      resolver = new CloudFormationResolver([resource]);
    }

    // Skip security group-to-security group rules for wide range check
    const isSecurityGroupRule = rule.SourceSecurityGroupId !== undefined ||
      rule.SourceSecurityGroupName !== undefined;

    if (isSecurityGroupRule) {
      return null; // Security group-to-security group rules are generally more restrictive
    }

    // Check for overly permissive CIDR ranges
    const cidrIp = resolver.resolve(rule.CidrIp);
    if (cidrIp.isResolved && cidrIp.value === '0.0.0.0/0') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Restrict ${accessType} traffic to specific IP ranges instead of ${cidrIp.value}.`
      );
    } else if (!cidrIp.isResolved && rule.CidrIp) {
      // If we can't resolve the CIDR, we need to fail the check
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Unable to verify CIDR range at scan time due to intrinsic functions. Ensure ${accessType} traffic is restricted to specific IP ranges.`
      );
    }

    // Check for overly permissive IPv6 CIDR ranges
    const cidrIpv6 = resolver.resolve(rule.CidrIpv6);
    if (cidrIpv6.isResolved && cidrIpv6.value === '::/0') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Restrict ${accessType} traffic to specific IPv6 ranges instead of ${cidrIpv6.value}.`
      );
    } else if (!cidrIpv6.isResolved && rule.CidrIpv6) {
      // If we can't resolve the CIDR, we need to fail the check
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Unable to verify IPv6 CIDR range at scan time due to intrinsic functions. Ensure ${accessType} traffic is restricted to specific IPv6 ranges.`
      );
    }

    // Check for wide CIDR ranges (less than /24 for IPv4)
    if (cidrIp.isResolved && typeof cidrIp.value === 'string') {
      const cidrParts = cidrIp.value.split('/');
      if (cidrParts.length === 2) {
        const prefix = parseInt(cidrParts[1], 10);
        if (!isNaN(prefix) && prefix < 24) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use a more restrictive CIDR range than ${cidrIp.value} for ${accessType} traffic.`
          );
        }
      }
    }

    return null;
  }
}

export default new FSxN001Rule();
