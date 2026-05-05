import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS11 Rule: Ensure that there is a mechanism to isolate tenant workloads to specific nodes.
 * 
 * Documentation: "Restricting tenant workloads to run on specific nodes can be used to increase isolation 
 * in the soft multi-tenancy model. With this approach, tenant-specific workloads are only run on nodes 
 * provisioned for the respective tenants. Affinity and anti-affinity is the simplest way to contrain 
 * pods to nodes with specific labels."
 * 
 * Note: This rule is more of a guidance than a strict rule as CloudFormation templates may not contain 
 * all the information needed to fully validate tenant workload isolation.
 */
export class EKS011Rule extends BaseRule {
  constructor() {
    super(
      'EKS-011',
      'HIGH',
      'EKS cluster does not have mechanisms to isolate tenant workloads to specific nodes',
      ['AWS::EKS::Cluster', 'AWS::EKS::Nodegroup', 'AWS::EKS::FargateProfile']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      // Check if this appears to be a multi-tenant cluster
      const isMultiTenant = this.isLikelyMultiTenantCluster(resource);

      if (isMultiTenant) {
        // Check if there are node groups with tenant labels
        const hasTenantNodeGroups = this.hasTenantNodeGroups(resource, allResources);

        if (!hasTenantNodeGroups) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (multi-tenant cluster without labeled node groups)`,
            `Create node groups with tenant-specific labels to enable workload isolation.`
          );
        }

        // Check if there are Fargate profiles with namespace selectors
        const hasFargateProfiles = this.hasFargateProfilesWithNamespaces(resource, allResources);

        if (!hasFargateProfiles && !hasTenantNodeGroups) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (multi-tenant cluster without Fargate profiles or labeled node groups)`,
            `Create Fargate profiles with namespace selectors or node groups with tenant-specific labels.`
          );
        }
      }
    }

    // Check if this is a node group
    if (resource.Type === 'AWS::EKS::Nodegroup') {
      const labels = resource.Properties?.Labels;

      // Check if the node group has tenant-related labels
      if (!labels || !this.hasTenantLabels(labels)) {
        // Check if this is part of a multi-tenant cluster
        const clusterName = resource.Properties?.ClusterName;
        const cluster = this.findClusterByName(clusterName, allResources);

        if (cluster && this.isLikelyMultiTenantCluster(cluster)) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (node group without tenant labels in multi-tenant cluster)`,
            `Add tenant-specific labels to the node group to enable workload isolation.`
          );
        }
      }

      // Check if the node group has taints to prevent non-tenant workloads
      const taints = resource.Properties?.Taints;

      if (labels && this.hasTenantLabels(labels) && (!taints || !Array.isArray(taints) || taints.length === 0)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (tenant node group without taints)`,
          `Add taints to the node group to prevent non-tenant workloads from being scheduled on tenant nodes.`
        );
      }
    }

    // Check if this is a Fargate profile
    if (resource.Type === 'AWS::EKS::FargateProfile') {
      const selectors = resource.Properties?.Selectors;

      if (!selectors || !Array.isArray(selectors) || selectors.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (Fargate profile without selectors)`,
          `Add namespace and label selectors to the Fargate profile to isolate tenant workloads.`
        );
      }

      // Check if selectors have namespace definitions
      const hasNamespaceSelectors = selectors.some(selector => selector.Namespace);

      if (!hasNamespaceSelectors) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (Fargate profile without namespace selectors)`,
          `Add namespace selectors to isolate tenant workloads.`
        );
      }

      // Check if selectors have label definitions for tenant isolation
      const hasLabelSelectors = selectors.some(selector => {
        const labels = selector.Labels;
        return labels && this.hasTenantLabels(labels);
      });

      if (!hasLabelSelectors) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (Fargate profile without tenant label selectors)`,
          `Add tenant-specific label selectors to isolate tenant workloads.`
        );
      }
    }

    return null;
  }

  private isLikelyMultiTenantCluster(resource: CloudFormationResource): boolean {
    // Check cluster name for multi-tenant indicators
    const clusterName = resource.Properties?.Name || resource.LogicalId;
    if (typeof clusterName === 'string') {
      const lowerName = clusterName.toLowerCase();
      if (
        lowerName.includes('multi') ||
        lowerName.includes('tenant') ||
        lowerName.includes('shared')
      ) {
        return true;
      }
    }

    // Check tags for multi-tenant indicators
    const tags = resource.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      for (const tag of tags) {
        if (
          (tag.Key === 'Environment' &&
            typeof tag.Value === 'string' &&
            (tag.Value.toLowerCase().includes('multi') ||
              tag.Value.toLowerCase().includes('shared'))) ||
          (tag.Key === 'Tenant' && tag.Value) ||
          (tag.Key === 'MultiTenant' && tag.Value === 'true')
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private hasTenantNodeGroups(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;

    // Look for node groups with tenant labels
    return allResources.some(resource => {
      if (resource.Type === 'AWS::EKS::Nodegroup' &&
        resource.Properties?.ClusterName === clusterName) {

        const labels = resource.Properties?.Labels;
        return labels && this.hasTenantLabels(labels);
      }
      return false;
    });
  }

  private hasFargateProfilesWithNamespaces(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;

    // Look for Fargate profiles with namespace selectors
    return allResources.some(resource => {
      if (resource.Type === 'AWS::EKS::FargateProfile' &&
        resource.Properties?.ClusterName === clusterName) {

        const selectors = resource.Properties?.Selectors;
        if (selectors && Array.isArray(selectors)) {
          return selectors.some(selector => {
            // Check for namespace selectors
            if (selector.Namespace) {
              const namespace = selector.Namespace.toLowerCase();
              return namespace.includes('tenant') ||
                namespace.includes('team') ||
                namespace.includes('customer') ||
                namespace.includes('user');
            }
            return false;
          });
        }
      }
      return false;
    });
  }

  private hasTenantLabels(labels: Record<string, string>): boolean {
    for (const key in labels) {
      const lowerKey = key.toLowerCase();
      const lowerValue = labels[key] && typeof labels[key] === 'string' ?
        labels[key].toLowerCase() : '';

      if (
        lowerKey.includes('tenant') ||
        lowerKey.includes('team') ||
        lowerKey.includes('customer') ||
        lowerKey.includes('user') ||
        lowerKey.includes('owner') ||
        lowerKey.includes('environment') ||
        lowerValue.includes('tenant') ||
        lowerValue.includes('team') ||
        lowerValue.includes('customer') ||
        lowerValue.includes('user')
      ) {
        return true;
      }
    }

    return false;
  }

  private findClusterByName(clusterName: string, allResources?: CloudFormationResource[]): CloudFormationResource | undefined {
    if (!allResources || !clusterName) {
      return undefined;
    }

    return allResources.find(resource =>
      resource.Type === 'AWS::EKS::Cluster' &&
      (resource.Properties?.Name === clusterName || resource.LogicalId === clusterName)
    );
  }
}

export default new EKS011Rule();
