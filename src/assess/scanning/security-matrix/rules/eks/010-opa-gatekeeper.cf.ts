import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * EKS10 Rule: Ensure that Open Policy Agent (OPA) & Gatekeeper are configured for the cluster.
 * 
 * Documentation: "Gatekeeper is a Kubernetes admission controller that enforces policies created with OPA. 
 * With OPA you can create a policy that runs pods from tenants on separate instances or at a higher priority 
 * than other tenants. A collection of common OPA policies can be found in the GitHub repository for this project."
 * 
 * Note: This rule is more of a guidance than a strict rule as CloudFormation templates may not contain 
 * all the information needed to fully validate OPA & Gatekeeper configuration.
 */
export class EKS010Rule extends BaseRule {
  constructor() {
    super(
      'EKS-010',
      'HIGH',
      'EKS cluster does not have Open Policy Agent (OPA) & Gatekeeper configured',
      ['AWS::EKS::Cluster', 'AWS::EKS::Addon']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an EKS cluster
    if (resource.Type === 'AWS::EKS::Cluster') {
      // Check if there's a Gatekeeper addon or custom resource for the cluster
      const hasGatekeeper = this.hasGatekeeperConfiguration(resource, allResources);

      if (!hasGatekeeper) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Install OPA Gatekeeper using EKS add-ons or Helm to enforce admission control policies.`
        );
      }

      // Check if there are any OPA policies defined
      const hasOpaPolicies = this.hasOpaPolicies(resource, allResources);

      if (!hasOpaPolicies) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} (no OPA policies found)`,
          `Define OPA policies (ConstraintTemplates and Constraints) to enforce security and compliance requirements.`
        );
      }
    }

    // Check if this is an EKS addon for Gatekeeper
    if (resource.Type === 'AWS::EKS::Addon') {
      const addonName = resource.Properties?.AddonName;

      if (addonName && typeof addonName === 'string' &&
        (addonName === 'gatekeeper' ||
          addonName.toLowerCase().includes('gatekeeper') ||
          addonName.toLowerCase().includes('opa'))) {

        // Check if the addon has a proper configuration
        const configurationValues = resource.Properties?.ConfigurationValues;

        if (!configurationValues) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description} (Gatekeeper addon without configuration)`,
            `Provide proper configuration values for the Gatekeeper addon.`
          );
        }
      }
    }

    return null;
  }

  private hasGatekeeperConfiguration(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    const clusterName = cluster.Properties?.Name || cluster.LogicalId;

    // Check for EKS addon for Gatekeeper
    const hasGatekeeperAddon = allResources.some(resource => {
      if (resource.Type === 'AWS::EKS::Addon' &&
        resource.Properties?.ClusterName === clusterName) {

        const addonName = resource.Properties?.AddonName;
        return addonName && typeof addonName === 'string' &&
          (addonName === 'gatekeeper' ||
            addonName.toLowerCase().includes('gatekeeper') ||
            addonName.toLowerCase().includes('opa'));
      }
      return false;
    });

    if (hasGatekeeperAddon) {
      return true;
    }

    // Check for custom resources that might be Gatekeeper
    const hasGatekeeperCustomResource = allResources.some(resource => {
      // Check for Helm chart resources
      if (resource.Type === 'Custom::AWSQS-KubernetesResource' ||
        resource.Type === 'Custom::HelmChart') {

        const manifest = resource.Properties?.Manifest;
        const chartName = resource.Properties?.Chart;
        const values = resource.Properties?.Values;

        if (chartName && typeof chartName === 'string' &&
          (chartName.includes('gatekeeper') || chartName.includes('opa'))) {
          return true;
        }

        if (manifest && typeof manifest === 'string' &&
          (manifest.includes('gatekeeper') || manifest.includes('OPA'))) {
          return true;
        }

        if (values && typeof values === 'string' &&
          (values.includes('gatekeeper') || values.includes('OPA'))) {
          return true;
        }
      }

      // Check for CloudFormation custom resources
      if (resource.Type.startsWith('Custom::') &&
        (resource.Type.includes('Gatekeeper') || resource.Type.includes('OPA'))) {
        return true;
      }

      return false;
    });

    return hasGatekeeperCustomResource;
  }

  private hasOpaPolicies(cluster: CloudFormationResource, allResources?: CloudFormationResource[]): boolean {
    if (!allResources) {
      return false;
    }

    // Check for custom resources that might be OPA policies
    return allResources.some(resource => {
      // Check for Kubernetes resources
      if (resource.Type === 'Custom::AWSQS-KubernetesResource' ||
        resource.Type === 'Custom::KubernetesResource') {

        const manifest = resource.Properties?.Manifest;

        if (manifest && typeof manifest === 'string') {
          return (manifest.includes('ConstraintTemplate') ||
            manifest.includes('Constraint') ||
            manifest.includes('kind: K8sPSPCapabilities') ||
            manifest.includes('kind: K8sRequiredLabels'));
        }
      }

      // Check for CloudFormation custom resources
      if (resource.Type.startsWith('Custom::') &&
        (resource.Type.includes('Constraint') || resource.Type.includes('OPA'))) {
        return true;
      }

      return false;
    });
  }
}

export default new EKS010Rule();
