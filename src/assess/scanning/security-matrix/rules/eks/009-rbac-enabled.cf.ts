import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS9 Rule: Ensure that role-based access control (RBAC) is enabled for the EKS cluster.
 * 
 * Documentation: "OpenID Connect allows Clients to verify the identity of the End-User based on the authentication 
 * performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an 
 * interoperable and REST-like manner. OIDC federation access allows you to assume IAM roles via the Secure Token 
 * Service (STS), enabling authentication with an OIDC provider, receiving a JSON Web Token (JWT), which in turn 
 * can be used to assume an IAM role. Kubernetes, on the other hand, can issue so-called projected service account 
 * tokens, which happen to be valid OIDC JWTs for pods."
 * 
 * Note: RBAC is enabled by default in EKS clusters, but this rule checks for explicit configuration and 
 * proper integration with AWS IAM.
 */
export class EKS009Rule extends BaseRule {
  constructor() {
    super(
      'EKS-009',
      'HIGH',
      'EKS cluster does not have role-based access control (RBAC) properly configured',
      ['AWS::EKS::Cluster', 'AWS::EKS::AccessEntry', 'AWS::EKS::AccessPolicy']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      // RBAC is enabled by default in EKS, but we should check for proper configuration

      // Check if there's an aws-auth ConfigMap reference or AccessEntry resources
      const hasAccessConfiguration = this.hasAccessConfiguration(resource, allResources);

      if (!hasAccessConfiguration) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no access configuration found)`,
          `Configure AWS IAM integration with Kubernetes RBAC using aws-auth ConfigMap or EKS Access Entries.`
        );
      }

      // Check if there are any access policies defined
      const hasAccessPolicies = this.hasAccessPolicies(resource, allResources);

      if (!hasAccessPolicies) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no access policies found)`,
          `Define access policies to control permissions for users and roles.`
        );
      }
    }

    // Check if this is an AccessEntry resource
    if (resource.Type === 'AWS::EKS::AccessEntry') {
      const principalArn = resource.Properties?.PrincipalArn;
      const accessPolicies = resource.Properties?.AccessPolicies;

      // Handle CloudFormation intrinsic functions for PrincipalArn
      if (typeof principalArn === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set PrincipalArn to an explicit value rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }

      if (!principalArn) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (AccessEntry without PrincipalArn)`,
          `Specify a PrincipalArn to identify the IAM entity.`
        );
      }

      // Handle CloudFormation intrinsic functions for AccessPolicies
      if (typeof accessPolicies === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set AccessPolicies to explicit values rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }

      if (!accessPolicies || !Array.isArray(accessPolicies) || accessPolicies.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (AccessEntry without AccessPolicies)`,
          `Assign appropriate access policies to control permissions.`
        );
      }
    }

    // Check if this is an AccessPolicy resource
    if (resource.Type === 'AWS::EKS::AccessPolicy') {
      const policyArn = resource.Properties?.PolicyArn;
      const accessScope = resource.Properties?.AccessScope;

      // Handle CloudFormation intrinsic functions for PolicyArn
      if (typeof policyArn === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set PolicyArn to an explicit value rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }

      if (!policyArn) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (AccessPolicy without PolicyArn)`,
          `Specify a PolicyArn to define the permissions.`
        );
      }

      // Handle CloudFormation intrinsic functions for AccessScope
      if (typeof accessScope === 'object') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set AccessScope to an explicit value rather than using CloudFormation functions that cannot be validated at scan time.`
        );
      }

      if (!accessScope) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (AccessPolicy without AccessScope)`,
          `Define an AccessScope to specify the scope of the policy.`
        );
      }
    }

    return null;
  }

  private hasAccessConfiguration(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;

    // Check for AccessEntry resources associated with this cluster
    const hasAccessEntries = allResources.some(resource =>
      resource.Type === 'AWS::EKS::AccessEntry' &&
      resource.Properties?.ClusterName === clusterName
    );

    if (hasAccessEntries) {
      return true;
    }

    // Check for ConfigMap resources that might be aws-auth
    const hasAwsAuthConfigMap = allResources.some(resource => {
      if (resource.Type === 'Custom::AWSQS-EKSClusterResource' ||
        resource.Type === 'Custom::EKSConfigMap') {
        const configMapName = resource.Properties?.ConfigMapName;
        const configMapData = resource.Properties?.ConfigMapData;

        return (configMapName === 'aws-auth' ||
          (configMapData &&
            (configMapData.mapRoles || configMapData.mapUsers)));
      }
      return false;
    });

    return hasAwsAuthConfigMap;
  }

  private hasAccessPolicies(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;

    // Check for AccessPolicy resources associated with this cluster
    const hasAccessPolicies = allResources.some(resource =>
      resource.Type === 'AWS::EKS::AccessPolicy' &&
      resource.Properties?.ClusterName === clusterName
    );

    if (hasAccessPolicies) {
      return true;
    }

    // Check for ConfigMap resources with role mappings
    const hasRoleMappings = allResources.some(resource => {
      if ((resource.Type === 'Custom::AWSQS-EKSClusterResource' ||
        resource.Type === 'Custom::EKSConfigMap') &&
        resource.Properties?.ConfigMapName === 'aws-auth') {

        const configMapData = resource.Properties?.ConfigMapData;
        if (configMapData && configMapData.mapRoles) {
          const mapRoles = configMapData.mapRoles;

          // Check if mapRoles contains role mappings with groups
          if (typeof mapRoles === 'string') {
            return mapRoles.includes('groups:');
          } else if (Array.isArray(mapRoles)) {
            return mapRoles.some((role: any) => role.groups && Array.isArray(role.groups));
          }
        }
      }
      return false;
    });

    return hasRoleMappings;
  }
}

export default new EKS009Rule();
