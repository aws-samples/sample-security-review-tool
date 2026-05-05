import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-002',
      'HIGH',
      'EKS cluster does not have control plane logs enabled',
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
        'Configure enabled_cluster_log_types with all required log types.'
      );
    }

    const requiredLogTypes = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'];
    const missingLogTypes = requiredLogTypes.filter(type => !enabledClusterLogTypes.includes(type));

    if (missingLogTypes.length > 0) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (missing log types: ${missingLogTypes.join(', ')})`,
        'Enable all required log types: api, audit, authenticator, controllerManager, and scheduler.'
      );
    }

    return null;
  }
}

export default new TfEks002Rule();
