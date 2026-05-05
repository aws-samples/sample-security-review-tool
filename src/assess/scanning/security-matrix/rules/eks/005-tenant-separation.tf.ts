import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-005',
      'HIGH',
      'EKS cluster may lack proper tenant separation mechanisms',
      ['aws_eks_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_eks_cluster') return null;

    if (!this.isLikelyMultiTenant(resource)) return null;

    const clusterName = resource.values?.name || resource.name;
    const hasFargateProfiles = allResources.some(r =>
      r.type === 'aws_eks_fargate_profile' &&
      r.values?.cluster_name === clusterName &&
      this.hasNamespaceSelector(r)
    );

    if (!hasFargateProfiles) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} (multi-tenant cluster without namespace separation)`,
        'Use Fargate profiles or node groups with labels to separate workloads by namespace.'
      );
    }

    return null;
  }

  private isLikelyMultiTenant(resource: TerraformResource): boolean {
    const name = (resource.values?.name || resource.name || '').toLowerCase();
    return name.includes('multi') || name.includes('tenant') || name.includes('shared');
  }

  private hasNamespaceSelector(profile: TerraformResource): boolean {
    const selectors = profile.values?.selector;
    if (!Array.isArray(selectors)) return false;
    return selectors.some((s: any) => s.namespace);
  }
}

export default new TfEks005Rule();
