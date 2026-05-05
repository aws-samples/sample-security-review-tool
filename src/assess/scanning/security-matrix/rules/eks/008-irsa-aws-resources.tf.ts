import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks008Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-008',
      'HIGH',
      'EKS cluster does not use IAM Roles for Service Accounts (IRSA) for AWS resource access',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    const hasOidcProvider = allResources.some(r =>
      r.type === 'aws_iam_openid_connect_provider' &&
      typeof r.values?.url === 'string' &&
      r.values.url.includes('oidc.eks')
    );

    if (!hasOidcProvider) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (OIDC provider not configured)`,
        'Create an aws_iam_openid_connect_provider resource for the EKS cluster to enable IAM Roles for Service Accounts (IRSA).'
      );
    }

    const hasIrsaRoles = allResources.some(r => {
      if (r.type !== 'aws_iam_role') return false;
      const assumeRolePolicy = r.values?.assume_role_policy;
      if (typeof assumeRolePolicy !== 'string') return false;
      return assumeRolePolicy.includes('oidc.eks') || assumeRolePolicy.includes('oidc-provider');
    });

    if (!hasIrsaRoles) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (no IAM roles with OIDC trust relationships found)`,
        'Create IAM roles with trust relationships to the EKS OIDC provider for service accounts.'
      );
    }

    return null;
  }
}

export default new TfEks008Rule();
