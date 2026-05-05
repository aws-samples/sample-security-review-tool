import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks009Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-009',
      'HIGH',
      'EKS cluster does not have role-based access control (RBAC) properly configured',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    const clusterName = resource.values?.name || resource.name;

    const hasAccessEntries = allResources.some(r =>
      r.type === 'aws_eks_access_entry' &&
      r.values?.cluster_name === clusterName
    );

    const hasAuthConfigMap = allResources.some(r =>
      r.type === 'kubernetes_config_map' &&
      r.values?.metadata?.[0]?.name === 'aws-auth'
    );

    if (!hasAccessEntries && !hasAuthConfigMap) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (no access configuration found)`,
        'Configure AWS IAM integration with Kubernetes RBAC using EKS Access Entries or aws-auth ConfigMap.'
      );
    }

    return null;
  }
}

export default new TfEks009Rule();
