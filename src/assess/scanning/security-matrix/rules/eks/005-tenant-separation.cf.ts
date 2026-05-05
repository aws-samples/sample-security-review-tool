import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS5 Rule: Ensure that there are accounts and account Users to separate tenants in a shared Kubernetes cluster.
 * 
 * Documentation: "User accounts are for humans. Service accounts are for processes, which run in pods. 
 * User accounts are intended to be global. Names must be unique across all namespaces of a cluster. 
 * Service accounts are namespaced. If the Cluster is shared, different services account and users have 
 * to be created for the namespace."
 * 
 * Note: This rule is more of a guidance than a strict rule as CloudFormation templates may not contain 
 * all the information needed to fully validate tenant separation in Kubernetes.
 */
export class EKS005Rule extends BaseRule {
  constructor() {
    super(
      'EKS-005',
      'HIGH',
      'EKS cluster may lack proper tenant separation mechanisms',
      ['AWS::EKS::Cluster', 'AWS::EKS::Addon', 'AWS::EKS::FargateProfile', 'AWS::EKS::IdentityProviderConfig']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // This rule is primarily guidance-based and difficult to fully automate through CloudFormation analysis
    // We'll look for indicators of multi-tenancy and proper separation

    if (resource.Type === 'AWS::EKS::Cluster') {
      // Check if this appears to be a multi-tenant cluster based on naming or tags
      const isMultiTenant = this.isLikelyMultiTenantCluster(resource);

      if (isMultiTenant) {
        // Check for identity provider configuration which is essential for proper user management
        const hasIdentityProvider = this.hasIdentityProviderConfig(resource, allResources);

        if (!hasIdentityProvider) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (multi-tenant cluster without identity provider configuration)`,
            `Configure an identity provider for proper user authentication and authorization.`
          );
        }

        // Check for namespace separation via Fargate profiles or other mechanisms
        const hasNamespaceSeparation = this.hasNamespaceSeparation(resource, allResources);

        if (!hasNamespaceSeparation) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (multi-tenant cluster without namespace separation)`,
            `Use Fargate profiles or other mechanisms to separate workloads by namespace.`
          );
        }
      }
    }

    // For identity provider resources, check if they're properly configured
    if (resource.Type === 'AWS::EKS::IdentityProviderConfig') {
      const type = resource.Properties?.Type;
      const config = resource.Properties?.IdentityProviderConfigName;

      if (type === 'oidc' && config) {
        // Check if the OIDC provider has groups claim configuration
        const oidcConfig = resource.Properties?.OidcIdentityProviderConfig;
        if (!oidcConfig || !oidcConfig.GroupsClaim) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (OIDC provider without groups claim)`,
            `Configure GroupsClaim in the OIDC provider to map external groups to Kubernetes RBAC.`
          );
        }
      }
    }

    // For Fargate profiles, check if they're using namespaces for separation
    if (resource.Type === 'AWS::EKS::FargateProfile') {
      const selectors = resource.Properties?.Selectors;

      if (!selectors || !Array.isArray(selectors) || selectors.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (Fargate profile without namespace selectors)`,
          `Configure namespace selectors to separate workloads by namespace.`
        );
      }

      // Check if selectors have namespace definitions
      const hasNamespaceSelectors = selectors.some(selector => selector.Namespace);

      if (!hasNamespaceSelectors) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (Fargate profile without namespace selectors)`,
          `Define specific namespaces in the selectors to separate workloads.`
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

  private hasIdentityProviderConfig(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;

    // Look for identity provider configurations referencing this cluster
    return allResources.some(resource =>
      resource.Type === 'AWS::EKS::IdentityProviderConfig' &&
      resource.Properties?.ClusterName === clusterName
    );
  }

  private hasNamespaceSeparation(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
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
          return selectors.some(selector => selector.Namespace);
        }
      }
      return false;
    });
  }
}

export default new EKS005Rule();
