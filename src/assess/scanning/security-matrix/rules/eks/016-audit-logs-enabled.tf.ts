import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks016Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-016',
      'HIGH',
      'EKS cluster does not have audit logs enabled for the control plane',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    const enabledClusterLogTypes = resource.values?.enabled_cluster_log_types;
    if (!enabledClusterLogTypes || !Array.isArray(enabledClusterLogTypes) || enabledClusterLogTypes.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Configure enabled_cluster_log_types with audit logs enabled.'
      );
    }

    if (!enabledClusterLogTypes.includes('audit')) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        "Enable audit logs by adding 'audit' to enabled_cluster_log_types."
      );
    }

    return null;
  }
}

export default new TfEks016Rule();
