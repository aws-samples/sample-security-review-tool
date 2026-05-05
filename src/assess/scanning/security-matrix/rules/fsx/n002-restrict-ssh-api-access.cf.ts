import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';
import { isReferenceToResource, extractResourceIdsFromReference } from '../../../utils/cloudformation-intrinsic-utils.js';

/**
 * FSxN2 Rule: Is SSH and HTTPS (API) access to the file-system and/or storage virtual machines (SVMs) restricted to appropriate entities?
 * 
 * Documentation: "SSH and API (HTTPS) access to the file system and SVMs should be restricted to specific sources (like a bastion)."
 */
export class FSxN002Rule extends BaseRule {
  constructor() {
    super(
      'FSxN-002',
      'HIGH',
      'SSH and API access to file system and SVMs is not restricted to appropriate entities',
      [
        'AWS::FSx::FileSystem',
        'AWS::FSx::StorageVirtualMachine'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // For FSx FileSystem resources, we need allResources for context
    if (resource.Type === 'AWS::FSx::FileSystem' && (!allResources || !Array.isArray(allResources))) {
      return null;
    }

    const resolver = new CloudFormationResolver(allResources || []);

    // For FSx FileSystem resources
    if (resource.Type === 'AWS::FSx::FileSystem') {
      const fileSystemType = resource.Properties?.FileSystemType;

      // This rule is primarily for ONTAP (FSxN) file systems
      const resolvedFileSystemType = resolver.resolve(fileSystemType);
      if (!resolvedFileSystemType.isResolved) {
        // If we can't resolve the file system type, provide guidance but don't fail
        // This handles CDK-generated tokenized values
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}. Note: Unable to verify file system type at scan time due to unresolvable values (possibly CDK-generated tokens). If this is an ONTAP file system, ensure it has appropriate security controls.`
        );
      }

      if (resolvedFileSystemType.value !== 'ONTAP') {
        return null;
      }

      const ontapConfiguration = resource.Properties?.OntapConfiguration;

      if (!ontapConfiguration) {
        return null;
      }

      // Check if there are any SVMs associated with this file system
      const svmResult = this.findAssociatedSVMs(resource, allResources || [], resolver);

      if (svmResult.hasUnresolvableReferences) {
        // If we found unresolvable references, provide guidance but don't fail
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}. Note: Found unresolvable references (possibly CDK-generated tokens) when checking for associated SVMs. Ensure all SVMs have appropriate access controls.`
        );
      }

      if (svmResult.svms.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Create Storage Virtual Machines (SVMs) with appropriate access controls.`
        );
      }

      // Check if the file system has security groups configured
      const securityGroupIds = ontapConfiguration.SecurityGroupIds;

      if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure security groups for the ONTAP file system to restrict SSH and API access.`
        );
      }

      // Check for unresolvable security group references
      let hasUnresolvableSecurityGroups = false;
      for (const sgId of securityGroupIds) {
        const resolvedSgId = resolver.resolve(sgId);
        if (!resolvedSgId.isResolved) {
          hasUnresolvableSecurityGroups = true;
          break;
        }
      }

      if (hasUnresolvableSecurityGroups) {
        // If we found unresolvable security group references, provide guidance but don't fail
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}. Note: Found unresolvable security group references (possibly CDK-generated tokens). Ensure security groups restrict SSH and API access to appropriate sources.`
        );
      }

      // Check if the file system is in a private subnet
      const preferredSubnetId = ontapConfiguration.PreferredSubnetId;

      if (!preferredSubnetId) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Deploy the ONTAP file system in a private subnet to restrict access.`
        );
      }

      // Check if the subnet is private by looking for route tables
      const subnetResult = this.isPrivateSubnet(preferredSubnetId, allResources || [], resolver);

      if (subnetResult.hasUnresolvableReferences) {
        // If we found unresolvable subnet references, provide guidance but don't fail
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}. Note: Found unresolvable subnet references (possibly CDK-generated tokens). Ensure the ONTAP file system is deployed in a private subnet without direct internet access.`
        );
      }

      if (!subnetResult.isPrivate) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Deploy the ONTAP file system in a private subnet without direct internet access.`
        );
      }
    }

    // For FSx StorageVirtualMachine resources
    if (resource.Type === 'AWS::FSx::StorageVirtualMachine') {
      // Skip if properties are missing
      if (!resource.Properties) {
        return null;
      }

      // Check if the SVM has proper authentication configured
      const activeDirectoryConfiguration = resource.Properties.ActiveDirectoryConfiguration;
      const svmAdminPassword = resource.Properties.SvmAdminPassword;

      // Check if the SVM admin password is properly secured
      if (svmAdminPassword) {
        // Check if the password is a literal string (not recommended)
        if (typeof svmAdminPassword === 'string') {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use AWS Secrets Manager or SSM Parameter Store to securely store and reference the SVM admin password.`
          );
        }

        // Check if the password is a reference to a secure parameter
        const isSecureReference = this.isSecureParameterReference(svmAdminPassword, resolver);

        if (!isSecureReference) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Use AWS Secrets Manager or SSM Parameter Store to securely store and reference the SVM admin password.`
          );
        }
      }

      // Check if Active Directory integration is configured for proper authentication
      if (!activeDirectoryConfiguration && !svmAdminPassword) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure Active Directory integration or secure password for proper authentication and access control.`
        );
      }

      // Check if the SVM has endpoints configured
      const endpoints = resource.Properties.Endpoints;

      if (endpoints) {
        // Check if the management endpoint is properly secured
        const managementEndpoint = endpoints.Management;

        if (managementEndpoint) {
          const ipAddressType = resolver.resolve(managementEndpoint.IpAddressType);

          if (!ipAddressType.isResolved) {
            // If we can't resolve the IP address type, we need to fail the check
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Unable to verify IP address type at scan time due to intrinsic functions. Ensure management endpoint uses private IP addresses only.`
            );
          }

          if (ipAddressType.value === 'PUBLIC') {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Configure the management endpoint to use private IP addresses only.`
            );
          }
        }
      }
    }

    return null;
  }

  /**
   * Finds SVMs associated with an FSx ONTAP file system
   * @param fsxResource The FSx file system resource
   * @param allResources All resources in the template
   * @param resolver CloudFormation resolver for handling intrinsic functions
   * @returns Object containing SVMs and a flag indicating if unresolvable references were found
   */
  private findAssociatedSVMs(fsxResource: CloudFormationResource, allResources: CloudFormationResource[], resolver: CloudFormationResolver): { svms: CloudFormationResource[], hasUnresolvableReferences: boolean } {
    const associatedSVMs: CloudFormationResource[] = [];
    let hasUnresolvableReferences = false;

    for (const resource of allResources) {
      if (resource.Type !== 'AWS::FSx::StorageVirtualMachine') {
        continue;
      }

      const fileSystemId = resource.Properties?.FileSystemId;

      if (!fileSystemId) {
        continue;
      }

      // Resolve the file system ID
      const resolvedFileSystemId = resolver.resolve(fileSystemId);

      if (resolvedFileSystemId.isResolved) {
        // Direct match with resolved value
        if (resolvedFileSystemId.value === fsxResource.LogicalId) {
          associatedSVMs.push(resource);
          continue;
        }
      } else {
        // If we can't resolve it, mark as having unresolvable references
        hasUnresolvableReferences = true;

        // Still try to match using other methods
        // Direct match with unresolved value
        if (fileSystemId === fsxResource.LogicalId) {
          associatedSVMs.push(resource);
          continue;
        }

        // Check for intrinsic function references
        if (isReferenceToResource(fileSystemId, fsxResource.LogicalId)) {
          associatedSVMs.push(resource);
          continue;
        }

        // Extract resource IDs from references
        const resourceIds = extractResourceIdsFromReference(fileSystemId);
        if (resourceIds.includes(fsxResource.LogicalId)) {
          associatedSVMs.push(resource);
        }

        // Check for CDK-specific patterns
        if (typeof fileSystemId === 'object' && fileSystemId !== null) {
          // Check for CDK token patterns
          const jsonString = JSON.stringify(fileSystemId);
          if (jsonString.includes('Token') || jsonString.includes('${') || jsonString.includes('Fn::GetAtt')) {
            // This is likely a CDK-generated token, conservatively add this SVM
            associatedSVMs.push(resource);
          }
        }
      }
    }

    return { svms: associatedSVMs, hasUnresolvableReferences };
  }

  /**
   * Checks if a subnet is private (no direct internet access)
   * @param subnetId The subnet ID to check
   * @param allResources All resources in the template
   * @param resolver CloudFormation resolver for handling intrinsic functions
   * @returns Object containing whether the subnet is private and if unresolvable references were found
   */
  private isPrivateSubnet(subnetId: string, allResources: CloudFormationResource[], resolver: CloudFormationResolver): { isPrivate: boolean, hasUnresolvableReferences: boolean } {
    let hasUnresolvableReferences = false;

    // Resolve the subnet ID
    const resolvedSubnetId = resolver.resolve(subnetId);
    if (!resolvedSubnetId.isResolved) {
      hasUnresolvableReferences = true;
    }

    // Find the subnet resource
    let subnetResource: CloudFormationResource | undefined;

    for (const resource of allResources) {
      if (resource.Type !== 'AWS::EC2::Subnet') {
        continue;
      }

      if (resolvedSubnetId.isResolved) {
        if (resource.LogicalId === resolvedSubnetId.value) {
          subnetResource = resource;
          break;
        }
      } else {
        if (resource.LogicalId === subnetId || isReferenceToResource(subnetId, resource.LogicalId)) {
          subnetResource = resource;
          break;
        }

        // Check for CDK-specific patterns
        if (typeof subnetId === 'object' && subnetId !== null) {
          const jsonString = JSON.stringify(subnetId);
          if (jsonString.includes('Token') || jsonString.includes('${') || jsonString.includes('Fn::GetAtt')) {
            // This is likely a CDK-generated token, conservatively assume it might match
            subnetResource = resource;
            hasUnresolvableReferences = true;
            break;
          }
        }
      }
    }

    if (!subnetResource) {
      // If we can't find the subnet resource, assume it's a reference to an existing subnet
      // We'll be conservative and assume it might be private
      return { isPrivate: true, hasUnresolvableReferences };
    }

    // Check if the subnet has MapPublicIpOnLaunch set to false
    const mapPublicIp = resolver.resolve(subnetResource.Properties?.MapPublicIpOnLaunch);

    if (!mapPublicIp.isResolved) {
      hasUnresolvableReferences = true;
    } else if (mapPublicIp.value === true) {
      return { isPrivate: false, hasUnresolvableReferences }; // Public subnet
    }

    // Check if the subnet is associated with a route table that has an internet gateway
    const routeTableAssociations = allResources.filter(res => {
      if (res.Type !== 'AWS::EC2::SubnetRouteTableAssociation') {
        return false;
      }

      const associationSubnetId = resolver.resolve(res.Properties?.SubnetId);

      if (!associationSubnetId.isResolved) {
        hasUnresolvableReferences = true;
        // Check for direct match or reference
        return res.Properties?.SubnetId === subnetId || isReferenceToResource(res.Properties?.SubnetId, subnetId);
      }

      return associationSubnetId.value === (resolvedSubnetId.isResolved ? resolvedSubnetId.value : subnetId);
    });

    for (const association of routeTableAssociations) {
      const routeTableId = association.Properties?.RouteTableId;

      if (!routeTableId) {
        continue;
      }

      const resolvedRouteTableId = resolver.resolve(routeTableId);
      if (!resolvedRouteTableId.isResolved) {
        hasUnresolvableReferences = true;
      }

      // Find the route table
      for (const resource of allResources) {
        if (resource.Type !== 'AWS::EC2::RouteTable') {
          continue;
        }

        let isMatchingRouteTable = false;

        if (resolvedRouteTableId.isResolved) {
          isMatchingRouteTable = resource.LogicalId === resolvedRouteTableId.value;
        } else {
          isMatchingRouteTable = resource.LogicalId === routeTableId || isReferenceToResource(routeTableId, resource.LogicalId);
        }

        if (isMatchingRouteTable) {
          // Check if the route table has a route to an internet gateway
          const routes = allResources.filter(res => {
            if (res.Type !== 'AWS::EC2::Route') {
              return false;
            }

            const routeRouteTableId = resolver.resolve(res.Properties?.RouteTableId);

            if (!routeRouteTableId.isResolved) {
              hasUnresolvableReferences = true;
              return res.Properties?.RouteTableId === resource.LogicalId ||
                isReferenceToResource(res.Properties?.RouteTableId, resource.LogicalId);
            }

            return routeRouteTableId.value === resource.LogicalId;
          });

          for (const route of routes) {
            const gatewayId = route.Properties?.GatewayId;

            if (!gatewayId) {
              continue;
            }

            const resolvedGatewayId = resolver.resolve(gatewayId);
            if (!resolvedGatewayId.isResolved) {
              hasUnresolvableReferences = true;
            }

            // Check if the gateway is an internet gateway
            for (const igwResource of allResources) {
              if (igwResource.Type !== 'AWS::EC2::InternetGateway') {
                continue;
              }

              let isMatchingGateway = false;

              if (resolvedGatewayId.isResolved) {
                isMatchingGateway = igwResource.LogicalId === resolvedGatewayId.value;
              } else {
                isMatchingGateway = igwResource.LogicalId === gatewayId || isReferenceToResource(gatewayId, igwResource.LogicalId);
              }

              if (isMatchingGateway) {
                return { isPrivate: false, hasUnresolvableReferences }; // Public subnet with internet gateway
              }
            }
          }
        }
      }
    }

    // If we couldn't find evidence that it's a public subnet, assume it's private
    return { isPrivate: true, hasUnresolvableReferences };
  }

  /**
   * Checks if a value is a reference to a secure parameter (SSM Parameter Store or Secrets Manager)
   * @param value The value to check
   * @param resolver CloudFormation resolver for handling intrinsic functions
   * @returns True if the value is a reference to a secure parameter, false otherwise
   */
  private isSecureParameterReference(value: any, resolver: CloudFormationResolver): boolean {
    // Try to resolve the value
    const resolvedValue = resolver.resolve(value);

    // If we can't resolve it, check for intrinsic functions that might indicate secure parameters
    if (!resolvedValue.isResolved) {
      // Check for Ref to a parameter
      if (value.Ref) {
        return true; // Assume it's a reference to a parameter
      }

      // Check for dynamic references to secure parameters
      if (value['Fn::Sub'] && typeof value['Fn::Sub'] === 'string') {
        const subTemplate = value['Fn::Sub'];
        return subTemplate.includes('ssm:') ||
          subTemplate.includes('secretsmanager:') ||
          subTemplate.includes('{{resolve:');
      }

      // Check for direct dynamic references
      if (value['Fn::Join'] && Array.isArray(value['Fn::Join']) &&
        value['Fn::Join'].length === 2 && Array.isArray(value['Fn::Join'][1])) {
        const joinParts = value['Fn::Join'][1];
        const joinedString = joinParts.join('');
        return joinedString.includes('ssm:') ||
          joinedString.includes('secretsmanager:') ||
          joinedString.includes('{{resolve:');
      }

      // Check for GetAtt from a secure resource
      if (value['Fn::GetAtt'] && Array.isArray(value['Fn::GetAtt']) && value['Fn::GetAtt'].length === 2) {
        const resourceType = value['Fn::GetAtt'][0];
        return resourceType.includes('Secret') || resourceType.includes('Parameter');
      }

      // Check for ImportValue that might be a secure parameter
      if (value['Fn::ImportValue']) {
        return true; // Assume it might be a secure parameter
      }

      // Check for CDK-specific patterns
      if (typeof value === 'object' && value !== null) {
        const jsonString = JSON.stringify(value);
        if (jsonString.includes('Token') ||
          jsonString.includes('${') ||
          jsonString.includes('CDK') ||
          jsonString.includes('Fn::GetAtt')) {
          // This is likely a CDK-generated token, check if it might be a secure parameter
          if (jsonString.includes('Secret') ||
            jsonString.includes('Parameter') ||
            jsonString.includes('ssm') ||
            jsonString.includes('secretsmanager')) {
            return true;
          }
        }
      }

      // If we can't determine if it's a secure reference, we need to fail the check
      return false;
    }

    // Handle direct string (should not be the case for secure parameters)
    if (typeof resolvedValue.value === 'string') {
      return false;
    }

    return false;
  }
}

export default new FSxN002Rule();
