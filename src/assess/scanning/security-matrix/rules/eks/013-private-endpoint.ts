import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS13 Rule: Ensure that EKS cluster has private endpoint configured.
 * 
 * Documentation: "Leave the cluster endpoint public and specify which CIDR blocks can communicate with the cluster endpoint.
 * Configure the EKS cluster endpoint to be private.
 * Configure public access with a set of whitelisted CIDR blocks and set private endpoint access to enabled."
 * 
 * Note: This rule is partially covered by Checkov rule CKV_AWS_58 which checks if EKS cluster endpoint access is restricted.
 * This rule adds additional checks for private endpoint configuration.
 */
export class EKS013Rule extends BaseRule {
  constructor() {
    super(
      'EKS-013',
      'HIGH',
      'EKS cluster does not have private endpoint properly configured',
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

    // Check if private endpoint access is enabled
    const endpointPrivateAccess = resourcesVpcConfig.EndpointPrivateAccess;
    const endpointPublicAccess = resourcesVpcConfig.EndpointPublicAccess;
    const publicAccessCidrs = resourcesVpcConfig.PublicAccessCidrs;

    // Handle CloudFormation intrinsic functions for EndpointPrivateAccess
    if (typeof endpointPrivateAccess === 'object') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EndpointPrivateAccess to an explicit boolean value (true) rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // Handle CloudFormation intrinsic functions for EndpointPublicAccess
    if (typeof endpointPublicAccess === 'object') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EndpointPublicAccess to an explicit boolean value (false) rather than using CloudFormation functions that cannot be validated at scan time.`
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

    // Case 1: Private endpoint access is disabled
    if (endpointPrivateAccess === false) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (private endpoint access is disabled)`,
        `Enable private endpoint access by setting EndpointPrivateAccess to true.`
      );
    }

    // Case 2: Public access is enabled without CIDR restrictions
    if (endpointPublicAccess === true && (!publicAccessCidrs || publicAccessCidrs.length === 0)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} (public access enabled without CIDR restrictions)`,
        `Either disable public access by setting EndpointPublicAccess to false, or restrict access with PublicAccessCidrs.`
      );
    }

    // Case 3: Public access is enabled with overly permissive CIDRs
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

    // Best practice: Private access enabled, public access disabled
    if (endpointPrivateAccess === true && endpointPublicAccess === true) {
      // This is acceptable if public access is restricted with CIDRs
      if (!publicAccessCidrs || publicAccessCidrs.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (public access is enabled without CIDR restrictions)`,
          `Restrict public access with specific CIDR blocks or disable public access entirely.`
        );
      }
    }

    // Ideal configuration: Private access enabled, public access disabled
    if (endpointPrivateAccess === true && endpointPublicAccess === false) {
      // This is the most secure configuration, no finding
      return null;
    }

    return null;
  }
}

export default new EKS013Rule();
