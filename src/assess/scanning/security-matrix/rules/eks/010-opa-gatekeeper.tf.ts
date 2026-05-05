import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks010Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-010',
      'HIGH',
      'EKS cluster does not have Open Policy Agent (OPA) & Gatekeeper configured',
      ['aws_eks_cluster', 'aws_eks_addon']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_eks_cluster') {
      const clusterName = resource.values?.name || resource.name;

      const hasGatekeeper = allResources.some(r => {
        if (r.type === 'aws_eks_addon' && r.values?.cluster_name === clusterName) {
          const addonName = r.values?.addon_name;
          return typeof addonName === 'string' &&
            (addonName.includes('gatekeeper') || addonName.includes('opa'));
        }
        if (r.type === 'helm_release') {
          const chart = r.values?.chart;
          return typeof chart === 'string' &&
            (chart.includes('gatekeeper') || chart.includes('opa'));
        }
        return false;
      });

      if (!hasGatekeeper) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Install OPA Gatekeeper using EKS add-ons or Helm to enforce admission control policies.'
        );
      }
    }

    return null;
  }
}

export default new TfEks010Rule();
