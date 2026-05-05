import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS8 Rule: Ensure that IAM Roles for Service Accounts (IRSA) is used to access AWS resources from containers.
 * 
 * Documentation: "OpenID Connect allows Clients to verify the identity of the End-User based on the authentication 
 * performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an 
 * interoperable and REST-like manner. OIDC federation access allows you to assume IAM roles via the Secure Token 
 * Service (STS), enabling authentication with an OIDC provider, receiving a JSON Web Token (JWT), which in turn 
 * can be used to assume an IAM role. Kubernetes, on the other hand, can issue so-called projected service account 
 * tokens, which happen to be valid OIDC JWTs for pods."
 */
export class EKS008Rule extends BaseRule {
  constructor() {
    super(
      'EKS-008',
      'HIGH',
      'EKS cluster does not use IAM Roles for Service Accounts (IRSA) for AWS resource access',
      ['AWS::EKS::Cluster', 'AWS::IAM::Role']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      // Check if OIDC provider is configured for the cluster
      const hasOidcProvider = this.hasOidcProviderForCluster(resource, allResources);

      if (!hasOidcProvider) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (OIDC provider not configured)`,
          `Configure an OIDC identity provider for the EKS cluster to enable IAM Roles for Service Accounts (IRSA).`
        );
      }

      // Check if there are IAM roles with trust relationships to the OIDC provider
      const hasIrsaRoles = this.hasIrsaRoles(resource, allResources);

      if (!hasIrsaRoles) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no IAM roles with OIDC trust relationships found)`,
          `Create IAM roles with trust relationships to the EKS OIDC provider for service accounts.`
        );
      }
    }

    // Check if this is an IAM role that might be used with EKS but doesn't have proper OIDC trust relationship
    if (resource.Type === 'AWS::IAM::Role') {
      const isEksRelatedRole = this.isEksRelatedRole(resource);

      if (isEksRelatedRole) {
        const hasOidcTrustRelationship = this.hasOidcTrustRelationship(resource);

        if (!hasOidcTrustRelationship) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (EKS-related IAM role without OIDC trust relationship)`,
            `Update the AssumeRolePolicyDocument to include a trust relationship with the EKS OIDC provider.`
          );
        }
      }
    }

    return null;
  }

  private hasOidcProviderForCluster(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    // Check if the cluster has an OIDC provider URL in its properties
    const oidcIssuerUrl = cluster.Properties?.Identity?.OidcIssuerUrl;
    if (oidcIssuerUrl) {
      return true;
    }

    // Check if there's an IAM OIDC provider resource that references this cluster
    if (allResources) {
      const clusterName = cluster.Properties?.Name || cluster.LogicalId;

      return allResources.some(resource => {
        if (resource.Type === 'AWS::IAM::OIDCProvider') {
          const url = resource.Properties?.Url;
          if (url && typeof url === 'string' && url.includes('eks')) {
            // Check if the URL or tags reference this cluster
            const tags = resource.Properties?.Tags;
            if (tags && Array.isArray(tags)) {
              return tags.some(tag =>
                tag.Key === 'eks:cluster-name' && tag.Value === clusterName
              );
            }
          }
        }
        return false;
      });
    }

    return false;
  }

  private hasIrsaRoles(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;
    const oidcIssuerUrl = cluster.Properties?.Identity?.OidcIssuerUrl;

    // Look for IAM roles with trust relationships to the OIDC provider
    return allResources.some(resource => {
      if (resource.Type === 'AWS::IAM::Role') {
        const assumeRolePolicyDocument = resource.Properties?.AssumeRolePolicyDocument;

        if (assumeRolePolicyDocument && assumeRolePolicyDocument.Statement) {
          const statements = Array.isArray(assumeRolePolicyDocument.Statement)
            ? assumeRolePolicyDocument.Statement
            : [assumeRolePolicyDocument.Statement];

          return statements.some((statement: any) => {
            if (statement.Principal && statement.Principal.Federated) {
              const federated = statement.Principal.Federated;

              // Check if the federated principal references an OIDC provider
              if (typeof federated === 'string') {
                return federated.includes('oidc-provider') ||
                  (oidcIssuerUrl && federated.includes(oidcIssuerUrl));
              }
            }
            return false;
          });
        }
      }
      return false;
    });
  }

  private isEksRelatedRole(role: CloudFormationResource): boolean {
    // Check role name for EKS indicators
    const roleName = role.Properties?.RoleName || role.LogicalId;
    if (typeof roleName === 'string') {
      const lowerName = roleName.toLowerCase();
      if (
        lowerName.includes('eks') ||
        lowerName.includes('kubernetes') ||
        lowerName.includes('k8s') ||
        lowerName.includes('pod') ||
        lowerName.includes('container')
      ) {
        return true;
      }
    }

    // Check tags for EKS indicators
    const tags = role.Properties?.Tags;
    if (tags && Array.isArray(tags)) {
      for (const tag of tags) {
        if (
          tag.Key === 'eks:cluster-name' ||
          (tag.Key === 'Service' && tag.Value === 'eks') ||
          (tag.Key === 'kubernetes.io/cluster/')
        ) {
          return true;
        }
      }
    }

    // Check if the role has policies that suggest it's for EKS
    const policies = role.Properties?.ManagedPolicyArns;
    if (policies && Array.isArray(policies)) {
      for (const policy of policies) {
        if (
          typeof policy === 'string' &&
          (policy.includes('EKS') || policy.includes('Kubernetes'))
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private hasOidcTrustRelationship(role: CloudFormationResource): boolean {
    const assumeRolePolicyDocument = role.Properties?.AssumeRolePolicyDocument;

    if (assumeRolePolicyDocument && assumeRolePolicyDocument.Statement) {
      const statements = Array.isArray(assumeRolePolicyDocument.Statement)
        ? assumeRolePolicyDocument.Statement
        : [assumeRolePolicyDocument.Statement];

      return statements.some((statement: any) => {
        // Check for OIDC federation
        if (statement.Principal && statement.Principal.Federated) {
          const federated = statement.Principal.Federated;

          if (typeof federated === 'string') {
            return federated.includes('oidc-provider') || federated.includes('oidc.eks');
          }
        }

        // Check for conditions that indicate IRSA
        if (statement.Condition) {
          const condition = statement.Condition;

          // Check for StringEquals or StringLike condition with oidc.eks
          if (condition.StringEquals || condition.StringLike) {
            const stringCondition = condition.StringEquals || condition.StringLike;

            for (const key in stringCondition) {
              if (key.includes('oidc.eks') || key.includes('amazonaws.com:sub')) {
                return true;
              }
            }
          }
        }

        return false;
      });
    }

    return false;
  }
}

export default new EKS008Rule();
