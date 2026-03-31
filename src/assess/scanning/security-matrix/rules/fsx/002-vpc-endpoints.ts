import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * FSx2 Rule: Confirm VPC endpoints to connect to FSx from your VPC without going over the public internet.
 * 
 * Note: General VPC endpoint configuration checks are handled by NET-VPC rules.
 * This rule focuses specifically on FSx VPC endpoint configuration.
 * 
 * Documentation: "Improved security - VPC endpoints allow you to connect to FSx APIs and file data transfer without traversing the public internet. All traffic stays within the AWS network."
 */
export class FSx002Rule extends BaseRule {
  constructor() {
    super(
      'FSx-002',
      'HIGH',
      'FSx file system does not use VPC endpoints for secure connectivity',
      [
        'AWS::FSx::FileSystem',
        'AWS::EC2::VPCEndpoint'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    const resolver = new CloudFormationResolver(allResources);

    // For FSx FileSystem resources
    if (resource.Type === 'AWS::FSx::FileSystem') {
      const vpcId = this.extractVpcId(resource, resolver);

      // Skip if we can't determine the VPC ID
      if (!vpcId) {
        return null;
      }

      // Check if there are any VPC endpoints for FSx in the same VPC
      if (allResources && Array.isArray(allResources)) {
        const hasFsxEndpoint = this.hasFsxEndpointInVpc(vpcId, allResources, resolver);

        if (!hasFsxEndpoint) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Create VPC endpoints for FSx service to ensure traffic stays within the AWS network.`
          );
        }
      } else {
        // If we don't have allResources, we can't check for VPC endpoints
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Create VPC endpoints for FSx service to ensure traffic stays within the AWS network.`
        );
      }
    }

    // For VPC Endpoint resources
    if (resource.Type === 'AWS::EC2::VPCEndpoint') {
      const serviceName = resource.Properties?.ServiceName;

      // Only evaluate FSx endpoints
      if (!serviceName || !this.isFsxServiceEndpoint(serviceName, resolver)) {
        return null; // Skip non-FSx endpoints
      }

      // Continue with FSx specific checks
      // Check if the endpoint is properly configured
      const vpcEndpointType = resource.Properties?.VpcEndpointType;

      // FSx requires Interface endpoints
      if (vpcEndpointType !== 'Interface') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure the FSx VPC endpoint as an Interface endpoint type.`
        );
      }

      // Check for private DNS enabled
      const privateDnsEnabled = resource.Properties?.PrivateDnsEnabled;

      if (privateDnsEnabled !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Enable private DNS for the FSx VPC endpoint to use the default FSx DNS hostname.`
        );
      }

      // Check for security groups
      const securityGroupIds = resource.Properties?.SecurityGroupIds;

      if (!securityGroupIds || (Array.isArray(securityGroupIds) && securityGroupIds.length === 0)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Configure security groups for the FSx VPC endpoint to control access.`
        );
      }
    }

    return null;
  }

  /**
   * Extracts the VPC ID from an FSx FileSystem resource
   * @param resource The FSx FileSystem resource
   * @param resolver CloudFormationResolver instance
   * @returns The VPC ID or null if not found
   */
  private extractVpcId(resource: CloudFormationResource, resolver: CloudFormationResolver): string | null {
    // Different FSx file system types have different property structures
    const fileSystemType = resource.Properties?.FileSystemType;

    if (fileSystemType === 'WINDOWS') {
      const windowsConfiguration = resource.Properties?.WindowsConfiguration;
      if (windowsConfiguration?.VpcConfiguration?.VpcId) {
        const resolved = resolver.resolve(windowsConfiguration.VpcConfiguration.VpcId);
        if (resolved.isResolved) {
          return resolved.value;
        } else {
          return null;
        }
      }
      return null;
    }

    if (fileSystemType === 'LUSTRE') {
      const lustreConfiguration = resource.Properties?.LustreConfiguration;
      if ((lustreConfiguration?.DeploymentType === 'PERSISTENT_1' ||
        lustreConfiguration?.DeploymentType === 'PERSISTENT_2') &&
        resource.Properties?.VpcId) {
        const resolved = resolver.resolve(resource.Properties.VpcId);
        if (resolved.isResolved) {
          return resolved.value;
        }
      }
      return null;
    }

    if (fileSystemType === 'ONTAP') {
      const ontapConfiguration = resource.Properties?.OntapConfiguration;
      if (ontapConfiguration?.PreferredSubnetId && resource.Properties?.VpcId) {
        const resolved = resolver.resolve(resource.Properties.VpcId);
        if (resolved.isResolved) {
          return resolved.value;
        }
      }
      return null;
    }

    if (fileSystemType === 'OPENZFS') {
      const openZFSConfiguration = resource.Properties?.OpenZFSConfiguration;
      if ((openZFSConfiguration?.DeploymentType === 'SINGLE_AZ_1' ||
        openZFSConfiguration?.DeploymentType === 'SINGLE_AZ_2') &&
        resource.Properties?.VpcId) {
        const resolved = resolver.resolve(resource.Properties.VpcId);
        if (resolved.isResolved) {
          return resolved.value;
        }
      }
      return null;
    }

    // For other cases, try to get VPC ID directly from properties
    if (resource.Properties?.VpcId) {
      const resolved = resolver.resolve(resource.Properties.VpcId);
      if (resolved.isResolved) {
        return resolved.value;
      }
    }

    return null;
  }

  /**
   * Checks if there are any FSx VPC endpoints in the specified VPC
   * @param vpcId The VPC ID to check
   * @param allResources All resources in the template
   * @param resolver CloudFormationResolver instance
   * @returns True if there are FSx endpoints in the VPC, false otherwise
   */
  private hasFsxEndpointInVpc(vpcId: string, allResources: CloudFormationResource[], resolver: CloudFormationResolver): boolean {
    // Get all VPC endpoints
    const vpcEndpoints = allResources.filter(res => res.Type === 'AWS::EC2::VPCEndpoint');

    // Check if any of them are for FSx and in the same VPC
    for (const endpoint of vpcEndpoints) {
      const endpointVpcId = endpoint.Properties?.VpcId;
      const serviceName = endpoint.Properties?.ServiceName;

      // Skip if VPC ID or service name is not specified
      if (!endpointVpcId || !serviceName) {
        continue;
      }

      // Check if this endpoint is in the same VPC
      const resolvedVpcId = resolver.resolve(endpointVpcId);
      let isSameVpc = false;

      if (resolvedVpcId.isResolved && resolvedVpcId.value === vpcId) {
        isSameVpc = true;
      } else if (resolvedVpcId.referencedResources.includes(vpcId)) {
        isSameVpc = true;
      }

      // If this endpoint is in the same VPC, check if it's for FSx
      if (isSameVpc && this.isFsxServiceEndpoint(serviceName, resolver)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Checks if a service name is for FSx
   * @param serviceName The service name to check
   * @param resolver CloudFormationResolver instance
   * @returns True if the service name is for FSx, false otherwise
   */
  private isFsxServiceEndpoint(serviceName: any, resolver: CloudFormationResolver): boolean {
    const resolved = resolver.resolve(serviceName);

    // If we can resolve the service name
    if (resolved.isResolved && typeof resolved.value === 'string') {
      return resolved.value.includes('fsx') ||
        resolved.value.includes('elasticfilesystem') ||
        (resolved.value.includes('com.amazonaws.') && resolved.value.includes('.fsx'));
    }

    // If we can't resolve it, we should fail safely
    return false;
  }
}

export default new FSx002Rule();
