import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS1 Rule: Ensure that Kubernetes APIs are not publicly accessible in the solution EKS cluster.
 * 
 * Documentation: "A solutions cluster's Kubernetes API server endpoint should not be publicly accessible from the Internet 
 * in order to avoid exposing private data and minimizing security risks. Solutions should only provide the API server 
 * endpoints be accessible from within a AWS Virtual Private Cloud (VPC)."
 * 
 * Note: This rule is partially covered by Checkov rule CKV_AWS_58 which checks if EKS cluster endpoint access is restricted.
 * This rule adds additional checks for specific configurations.
 */
export class EKS001Rule extends BaseRule {
  constructor() {
    super(
      'EKS-001',
      'HIGH',
      'EKS cluster has publicly accessible Kubernetes API endpoints',
      ['AWS::EKS::Cluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type !== 'AWS::EKS::Cluster') {
      return null;
    }

    const resourcesVpcConfig = resource.Properties?.ResourcesVpcConfig;
    if (!resourcesVpcConfig) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure ResourcesVpcConfig with appropriate endpoint access settings.`
      );
    }

    // Check if endpoint public access is disabled
    const endpointPublicAccess = resourcesVpcConfig.EndpointPublicAccess;
    const endpointPrivateAccess = resourcesVpcConfig.EndpointPrivateAccess;
    const publicAccessCidrs = resourcesVpcConfig.PublicAccessCidrs;

    // Handle CloudFormation intrinsic functions for EndpointPublicAccess
    if (typeof endpointPublicAccess === 'object') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EndpointPublicAccess to an explicit boolean value (false) rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Handle CloudFormation intrinsic functions for EndpointPrivateAccess
    if (typeof endpointPrivateAccess === 'object') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EndpointPrivateAccess to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Handle CloudFormation intrinsic functions for PublicAccessCidrs
    if (typeof publicAccessCidrs === 'object') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set PublicAccessCidrs to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Case 1: If public access is enabled without restrictions, flag it
    if (endpointPublicAccess === true && (!publicAccessCidrs || publicAccessCidrs.length === 0)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (public access enabled without CIDR restrictions)`,
        `Either disable public access by setting EndpointPublicAccess to false, or restrict access with PublicAccessCidrs.`
      );
    }

    // Case 2: If public access is enabled with overly permissive CIDRs, flag it
    if (endpointPublicAccess === true && publicAccessCidrs && Array.isArray(publicAccessCidrs)) {
      const hasOverlyPermissiveCidr = publicAccessCidrs.some(cidr =>
        cidr === '0.0.0.0/0' || cidr === '::/0');

      if (hasOverlyPermissiveCidr) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (public access enabled with overly permissive CIDR '0.0.0.0/0' or '::/0')`,
          `Restrict public access to specific IP ranges or disable public access entirely.`
        );
      }
    }

    // Case 3: If private access is disabled, recommend enabling it
    if (endpointPrivateAccess === false) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (private access is disabled)`,
        `Enable private access by setting EndpointPrivateAccess to true to allow access from within the VPC.`
      );
    }

    // Best practice: Public access disabled, private access enabled
    if (endpointPublicAccess === true && endpointPrivateAccess === true) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (public access is enabled)`,
        `Consider disabling public access by setting EndpointPublicAccess to false and rely solely on private access from within the VPC.`
      );
    }

    return null;
  }
}

export default new EKS001Rule();
