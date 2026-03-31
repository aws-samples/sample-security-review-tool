import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Redshift001Rule extends BaseRule {
  constructor() {
    super(
      'REDSHIFT-001',
      'HIGH',
      'RedShift cluster parameter group does not have SSL enabled',
      ['AWS::Redshift::Cluster', 'AWS::Redshift::ClusterParameterGroup'] // Fixed: lowercase 's' in Redshift
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties for any resource type
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add Parameters with 'require_ssl' parameter set to 'true' to enforce SSL connections.`
      );
    }

    if (resource.Type === 'AWS::Redshift::ClusterParameterGroup') {
      return this.evaluateParameterGroup(resource, stackName);
    }

    if (resource.Type === 'AWS::Redshift::Cluster') {
      return this.evaluateCluster(resource, stackName, allResources || []);
    }

    return null;
  }

  private evaluateParameterGroup(resource: CloudFormationResource, stackName: string): ScanResult | null {
    // Check if Properties exists
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add Parameters with 'require_ssl' parameter set to 'true' to enforce SSL connections.`
      );
    }

    // Check if the parameter group has SSL enabled
    const parameters = resource.Properties.Parameters;

    if (!parameters || !Array.isArray(parameters)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`, `Add 'require_ssl' parameter with value 'true' to enforce SSL connections.`
      );
    }

    // Find the require_ssl parameter in the parameters array
    const requireSslParam = parameters.find((param: any) =>
      param.ParameterName === 'require_ssl'
    );

    if (!requireSslParam) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add 'require_ssl' parameter with value 'true' to enforce SSL connections.`
      );
    }

    const requireSslValue = requireSslParam.ParameterValue;

    // If require_ssl is explicitly set to false or a non-true value
    if (requireSslValue === false || requireSslValue === 'false' || requireSslValue === '0') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set 'require_ssl' parameter to 'true' to enforce SSL connections.`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof requireSslValue === 'object') {
      // We can't determine the actual value at scan time, so we'll assume it's compliant
      // This is a limitation of static analysis of CloudFormation templates
      return null;
    }

    // If require_ssl is true or 'true' or '1', the parameter group is compliant
    if (requireSslValue === true || requireSslValue === 'true' || requireSslValue === '1') {
      return null;
    }

    // For any other value, consider it non-compliant
    return this.createScanResult(
      resource,
      stackName,
      `${this.description}`,
      `Set 'require_ssl' parameter to 'true' to enforce SSL connections.`
    );
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[]): ScanResult | null {
    // Check if the cluster has a parameter group that enforces SSL
    const paramGroupName = this.getResourceId(resource.Properties?.ClusterParameterGroupName);

    // If no parameter group is specified, the cluster is using the default parameter group
    // As of January 2025, the default parameter group has SSL enabled, but we should still flag this
    // for explicit configuration
    if (!paramGroupName) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Specify a ClusterParameterGroupName with 'require_ssl' set to 'true' for explicit SSL configuration.`
      );
    }

    // Find the parameter group resource in the same template
    const paramGroup = this.findParameterGroupByName(paramGroupName, allResources);

    // If the parameter group is defined in the same template, skip evaluation here
    // to avoid duplicate results. The parameter group will be evaluated separately.
    if (paramGroup) {
      return null;
    }

    // If we can't find the parameter group in the template, it's external/pre-existing
    // We can't verify SSL settings for external parameter groups, so assume compliant
    // This could be enhanced to check external resources if needed
    return null;
  }

  private findParameterGroupByName(name: string, allResources: CloudFormationResource[]): CloudFormationResource | null {
    return allResources.find(r =>
      r.Type === 'AWS::Redshift::ClusterParameterGroup' && // Fixed: lowercase 's'
      (r.LogicalId === name || r.Properties?.ParameterGroupName === name)
    ) || null;
  }

  private getResourceId(value: any): string | null {
    if (typeof value === 'string') {
      return value;
    }

    if (typeof value === 'object' && value?.Ref) {
      return value.Ref;
    }

    return null;
  }
}

export default new Redshift001Rule();
