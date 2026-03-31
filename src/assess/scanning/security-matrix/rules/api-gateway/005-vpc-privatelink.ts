import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * APIG5 Rule: Use VPC Private Link for API Gateways when they are used by VPC-connected entities
 * 
 * Documentation: "Use VPC PrivateLink for API Gateways when they are used by VPC-connected entities, 
 * like EC2 instances or VPC-connected Lambda functions. VPC PrivateLink assigns private IP addresses 
 * to VPC resources, but makes them reachable across VPC boundaries. This eliminates the possibility 
 * that an API GW is made public, and it allows VPC-based callers to invoke APIs even when their VPC 
 * subnet has no route to the Internet."
 */
export class ApiGw005Rule extends BaseRule {
  constructor() {
    super(
      'API-GW-005',
      'MEDIUM',
      'API Gateway does not use VPC PrivateLink for VPC-connected entities',
      ['AWS::ApiGateway::RestApi', 'AWS::EC2::VPCEndpoint']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!allResources) {
      return null;
    }

    // First pass: Collect information about APIs and VPC endpoints
    const resourceInfo = this.collectResourceInformation(allResources);

    if (resource.Type === 'AWS::ApiGateway::RestApi') {
      return this.evaluateRestApi(resource, stackName, resourceInfo);
    }

    if (resource.Type === 'AWS::EC2::VPCEndpoint') {
      return this.evaluateVpcEndpoint(resource, stackName);
    }

    return null;
  }

  private collectResourceInformation(resources: CloudFormationResource[]): {
    privateApis: Map<string, { logicalId: string, hasVpcEndpoint: boolean }>;
    vpcEndpoints: Map<string, { logicalId: string, isValid: boolean, vpcId: string | null }>;
    vpcs: Set<string>;
    vpcConnectedResources: boolean;
  } {
    const privateApis = new Map<string, { logicalId: string, hasVpcEndpoint: boolean }>();
    const vpcEndpoints = new Map<string, { logicalId: string, isValid: boolean, vpcId: string | null }>();
    const vpcs = new Set<string>();
    let vpcConnectedResources = false;

    // First pass: collect all private APIs and VPC endpoints
    for (const resource of resources) {
      if (resource.Type === 'AWS::ApiGateway::RestApi') {
        const endpointConfiguration = resource.Properties?.EndpointConfiguration;

        if (endpointConfiguration) {
          const types = endpointConfiguration.Types;

          if (types && Array.isArray(types) && types.includes('PRIVATE')) {
            privateApis.set(resource.LogicalId, {
              logicalId: resource.LogicalId,
              hasVpcEndpoint: false
            });
          }
        }
      }
      else if (resource.Type === 'AWS::EC2::VPCEndpoint') {
        const serviceName = resource.Properties?.ServiceName;

        if (serviceName && typeof serviceName === 'string' && serviceName.includes('execute-api')) {
          const vpcId = this.resolveReference(resource.Properties?.VpcId);
          const subnetIds = resource.Properties?.SubnetIds;
          const securityGroupIds = resource.Properties?.SecurityGroupIds;
          const privateDnsEnabled = resource.Properties?.PrivateDnsEnabled;

          // Check if the VPC endpoint is configured correctly
          const isValid =
            subnetIds &&
            Array.isArray(subnetIds) &&
            subnetIds.length > 0 &&
            securityGroupIds &&
            Array.isArray(securityGroupIds) &&
            securityGroupIds.length > 0 &&
            privateDnsEnabled === true;

          vpcEndpoints.set(resource.LogicalId, {
            logicalId: resource.LogicalId,
            isValid,
            vpcId
          });

          // Track VPCs that have API Gateway endpoints
          if (vpcId) {
            vpcs.add(vpcId);
          }
        }
      }
      // Check for VPC-connected resources like EC2 or Lambda functions in VPC
      else if (resource.Type === 'AWS::EC2::Instance' ||
        resource.Type === 'AWS::AutoScaling::LaunchConfiguration' ||
        resource.Type === 'AWS::EC2::LaunchTemplate') {
        vpcConnectedResources = true;
      }
      else if (resource.Type === 'AWS::Lambda::Function') {
        const vpcConfig = resource.Properties?.VpcConfig;
        if (vpcConfig && vpcConfig.SubnetIds && Array.isArray(vpcConfig.SubnetIds) && vpcConfig.SubnetIds.length > 0) {
          vpcConnectedResources = true;
        }
      }
    }

    // Second pass: mark private APIs that have VPC endpoints
    if (vpcEndpoints.size > 0) {
      // Check if there's at least one valid VPC endpoint for API Gateway
      const validEndpoints = Array.from(vpcEndpoints.values()).filter(endpoint => endpoint.isValid);

      if (validEndpoints.length > 0) {
        // If we have valid endpoints, we'll consider the private APIs to be accessible
        for (const [apiId, api] of privateApis) {
          api.hasVpcEndpoint = true;
        }
      }
    }

    return { privateApis, vpcEndpoints, vpcs, vpcConnectedResources };
  }

  private evaluateRestApi(
    resource: CloudFormationResource,
    stackName: string,
    resourceInfo: ReturnType<typeof this.collectResourceInformation>
  ): ScanResult | null {
    const { privateApis, vpcEndpoints, vpcConnectedResources } = resourceInfo;

    // Only evaluate if we have VPC-connected resources
    if (!vpcConnectedResources) {
      return null;
    }

    // Check if this is a private API
    const endpointConfiguration = resource.Properties?.EndpointConfiguration;
    const isPrivate = endpointConfiguration?.Types &&
      Array.isArray(endpointConfiguration.Types) &&
      endpointConfiguration.Types.includes('PRIVATE');

    // If this is a public API and we have VPC-connected resources, suggest using PrivateLink
    if (!isPrivate) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (public API with VPC-connected resources)`,
        `Consider using a private API with VPC PrivateLink for secure access from VPC resources.`
      );
    }

    // If this is a private API, check if it has VPC endpoints
    const api = privateApis.get(resource.LogicalId);

    // If there are no VPC endpoints at all in the template
    if (vpcEndpoints.size === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no API Gateway VPC endpoints found)`,
        `Create an AWS::EC2::VPCEndpoint resource with ServiceName for API Gateway (execute-api) to enable PrivateLink access.`
      );
    }

    // If there are VPC endpoints but none are valid
    if (vpcEndpoints.size > 0 && !Array.from(vpcEndpoints.values()).some(endpoint => endpoint.isValid)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (VPC endpoints found but not properly configured)`,
        `Configure VPC endpoints with SubnetIds, SecurityGroupIds, and set PrivateDnsEnabled to true.`
      );
    }

    // If this specific API doesn't have a VPC endpoint
    if (api && !api.hasVpcEndpoint) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (no valid VPC endpoints found for this API)`,
        `Create a properly configured AWS::EC2::VPCEndpoint resource for API Gateway with ServiceName containing 'execute-api'.`
      );
    }

    return null;
  }

  private evaluateVpcEndpoint(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Check if this is an API Gateway VPC endpoint
    const serviceName = resource.Properties?.ServiceName;

    // Only evaluate API Gateway endpoints
    if (!serviceName || typeof serviceName !== 'string' || !serviceName.includes('execute-api')) {
      return null;
    }

    // Check if the VPC endpoint is configured correctly for PrivateLink
    const vpcId = resource.Properties?.VpcId;
    const subnetIds = resource.Properties?.SubnetIds;
    const securityGroupIds = resource.Properties?.SecurityGroupIds;
    const privateDnsEnabled = resource.Properties?.PrivateDnsEnabled;
    const vpcEndpointType = resource.Properties?.VpcEndpointType;

    // VPC ID is required
    if (!vpcId) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (missing VPC ID)`,
        `Add VpcId property to the VPC endpoint.`
      );
    }

    // For Interface VPC endpoints (which API Gateway uses), subnet IDs and security group IDs should be specified
    if (vpcEndpointType === 'Interface' || !vpcEndpointType) { // Default is Interface if not specified
      if (!subnetIds || !Array.isArray(subnetIds) || subnetIds.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (missing subnet IDs)`,
          `Add SubnetIds property with at least one subnet ID.`
        );
      }

      if (!securityGroupIds || !Array.isArray(securityGroupIds) || securityGroupIds.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (missing security group IDs)`,
          `Add SecurityGroupIds property with at least one security group ID.`
        );
      }

      // Private DNS should be enabled for API Gateway VPC endpoints
      if (privateDnsEnabled !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (private DNS not enabled)`,
          `Set PrivateDnsEnabled to true for the VPC endpoint.`
        );
      }
    } else if (vpcEndpointType === 'Gateway') {
      // API Gateway doesn't support Gateway endpoints, only Interface endpoints
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (API Gateway requires Interface VPC endpoints, not Gateway)`,
        `Change VpcEndpointType to 'Interface'.`
      );
    }

    return null;
  }

  private resolveReference(ref: any): string | null {
    if (!ref) {
      return null;
    }

    if (typeof ref === 'string') {
      return ref;
    }

    if (typeof ref === 'object' && ref.Ref) {
      return ref.Ref;
    }

    return null;
  }
}

export default new ApiGw005Rule();
