import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-003',
      'HIGH',
      'Database does not have encryption in transit enabled',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      const parameterGroupName = resource.values?.parameter_group_name;
      if (parameterGroupName && this.parameterGroupEnforcesSsl(parameterGroupName, allResources)) {
        return null;
      }

      return this.createScanResult(
        resource,
        projectName,
        this.description,
        "Ensure the DB parameter group sets 'rds.force_ssl' to 1 to enforce SSL connections."
      );
    }

    if (resource.type === 'aws_rds_cluster') {
      const parameterGroupName = resource.values?.db_cluster_parameter_group_name;
      if (parameterGroupName && this.clusterParameterGroupEnforcesSsl(parameterGroupName, allResources)) {
        return null;
      }

      return this.createScanResult(
        resource,
        projectName,
        this.description,
        "Ensure the DB cluster parameter group sets 'rds.force_ssl' to 1 to enforce SSL connections."
      );
    }

    return null;
  }

  private parameterGroupEnforcesSsl(groupName: string, allResources: TerraformResource[]): boolean {
    const paramGroup = allResources.find(r =>
      r.type === 'aws_db_parameter_group' && r.name === groupName
    );

    if (!paramGroup) return false;
    return this.hasForceSSLParameter(paramGroup);
  }

  private clusterParameterGroupEnforcesSsl(groupName: string, allResources: TerraformResource[]): boolean {
    const paramGroup = allResources.find(r =>
      r.type === 'aws_rds_cluster_parameter_group' && r.name === groupName
    );

    if (!paramGroup) return false;
    return this.hasForceSSLParameter(paramGroup);
  }

  private hasForceSSLParameter(paramGroup: TerraformResource): boolean {
    const parameters = paramGroup.values?.parameter;
    if (!Array.isArray(parameters)) return false;

    return parameters.some((param: any) =>
      (param.name === 'rds.force_ssl' && param.value === '1') ||
      (param.name === 'ssl' && param.value === '1')
    );
  }
}

export default new TfRds003Rule();
