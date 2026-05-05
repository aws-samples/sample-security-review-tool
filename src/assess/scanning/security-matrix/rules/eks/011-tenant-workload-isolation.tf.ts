import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEks011Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EKS-011',
      'HIGH',
      'EKS cluster does not have mechanisms to isolate tenant workloads to specific nodes',
      ['aws_eks_cluster', 'aws_eks_node_group']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_eks_cluster') {
      if (!this.isLikelyMultiTenant(resource)) return null;

      const clusterName = resource.values?.name || resource.name;
      const hasTenantNodeGroups = allResources.some(r =>
        r.type === 'aws_eks_node_group' &&
        r.values?.cluster_name === clusterName &&
        this.hasTenantLabels(r.values?.labels)
      );

      if (!hasTenantNodeGroups) {
        return this.createScanResult(
          resource,
          projectName,
          `${this.description} (multi-tenant cluster without labeled node groups)`,
          'Create node groups with tenant-specific labels to enable workload isolation.'
        );
      }
    }

    if (resource.type === 'aws_eks_node_group') {
      const labels = resource.values?.labels;
      if (labels && this.hasTenantLabels(labels)) {
        const taints = resource.values?.taint;
        if (!taints || !Array.isArray(taints) || taints.length === 0) {
          return this.createScanResult(
            resource,
            projectName,
            `${this.description} (tenant node group without taints)`,
            'Add taints to the node group to prevent non-tenant workloads from being scheduled on tenant nodes.'
          );
        }
      }
    }

    return null;
  }

  private isLikelyMultiTenant(resource: TerraformResource): boolean {
    const name = (resource.values?.name || resource.name || '').toLowerCase();
    return name.includes('multi') || name.includes('tenant') || name.includes('shared');
  }

  private hasTenantLabels(labels: any): boolean {
    if (!labels || typeof labels !== 'object') return false;

    for (const key of Object.keys(labels)) {
      const lowerKey = key.toLowerCase();
      if (lowerKey.includes('tenant') || lowerKey.includes('team') ||
        lowerKey.includes('customer') || lowerKey.includes('owner')) {
        return true;
      }
    }
    return false;
  }
}

export default new TfEks011Rule();
