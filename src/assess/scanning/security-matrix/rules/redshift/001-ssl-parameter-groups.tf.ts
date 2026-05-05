import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRedshift001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'REDSHIFT-001',
      'HIGH',
      'RedShift cluster parameter group does not have SSL enabled',
      ['aws_redshift_cluster', 'aws_redshift_parameter_group']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_redshift_parameter_group') {
      return this.evaluateParameterGroup(resource, projectName);
    }

    if (resource.type === 'aws_redshift_cluster') {
      return this.evaluateCluster(resource, projectName, allResources);
    }

    return null;
  }

  private evaluateParameterGroup(resource: TerraformResource, projectName: string): ScanResult | null {
    const parameters = resource.values?.parameter;

    if (!parameters || !Array.isArray(parameters)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add a parameter with name "require_ssl" and value "true" to enforce SSL connections.`
      );
    }

    const requireSslParam = parameters.find(
      (param: any) => param.name === 'require_ssl'
    );

    if (!requireSslParam) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add a parameter with name "require_ssl" and value "true" to enforce SSL connections.`
      );
    }

    const value = requireSslParam.value;
    if (value === 'false' || value === '0' || value === false) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set the "require_ssl" parameter value to "true" to enforce SSL connections.`
      );
    }

    return null;
  }

  private evaluateCluster(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const paramGroupName = resource.values?.cluster_parameter_group_name;

    if (!paramGroupName) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Specify a cluster_parameter_group_name with "require_ssl" set to "true" for explicit SSL configuration.`
      );
    }

    const paramGroup = allResources.find(
      r => r.type === 'aws_redshift_parameter_group' &&
        (r.values?.name === paramGroupName || r.address === paramGroupName)
    );

    if (paramGroup) {
      return null;
    }

    return null;
  }
}

export default new TfRedshift001Rule();
