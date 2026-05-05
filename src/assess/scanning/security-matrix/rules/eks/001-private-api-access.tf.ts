import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-001',
      'HIGH',
      'EKS cluster has publicly accessible Kubernetes API endpoints',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    const vpcConfig = resource.values?.vpc_config;
    if (!vpcConfig || !Array.isArray(vpcConfig) || vpcConfig.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Configure vpc_config with appropriate endpoint access settings.'
      );
    }

    const config = vpcConfig[0];
    const endpointPublicAccess = config.endpoint_public_access;
    const endpointPrivateAccess = config.endpoint_private_access;
    const publicAccessCidrs = config.public_access_cidrs;

    if (endpointPublicAccess === true && (!publicAccessCidrs || publicAccessCidrs.length === 0)) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (public access enabled without CIDR restrictions)`,
        'Either disable public access by setting endpoint_public_access = false, or restrict access with public_access_cidrs.'
      );
    }

    if (endpointPublicAccess === true && Array.isArray(publicAccessCidrs)) {
      if (publicAccessCidrs.includes('0.0.0.0/0') || publicAccessCidrs.includes('::/0')) {
        return this.createScanResult(
          resource,
          projectName,
          `${this.description} (public access enabled with overly permissive CIDR)`,
          'Restrict public access to specific IP ranges or disable public access entirely.'
        );
      }
    }

    if (endpointPrivateAccess === false) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (private access is disabled)`,
        'Enable private access by setting endpoint_private_access = true to allow access from within the VPC.'
      );
    }

    if (endpointPublicAccess === true && endpointPrivateAccess === true) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (public access is enabled)`,
        'Consider disabling public access by setting endpoint_public_access = false and rely solely on private access from within the VPC.'
      );
    }

    return null;
  }
}

export default new TfEks001Rule();
