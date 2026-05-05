import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds003Rule extends BaseRule {
  constructor() {
    super(
      'RDS-003',
      'HIGH',
      'Database does not have encryption in transit enabled',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Check if the instance belongs to a cluster
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;

      // If the instance belongs to a cluster, skip checking it to avoid duplicate issues
      if (dbClusterIdentifier) {
        return null;
      }

      // Check if SSL is enforced directly in the instance parameters
      if (this.hasDirectSslEnforcement(resource)) {
        return null;
      }

      // Check if the instance references a parameter group that enforces SSL
      if (allResources) {
        const paramGroupName = this.getResourceId(resource.Properties?.DBParameterGroupName);
        if (paramGroupName) {
          const paramGroup = this.findDbParameterGroupByName(paramGroupName, allResources);

          if (paramGroup && this.parameterGroupEnforcesSsl(paramGroup)) {
            return null;
          }
        }
      }

      // No SSL enforcement found
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Ensure the DB parameter group sets 'rds.force_ssl' to true or 'ssl' to 1 to enforce SSL connections.`
      );
    }

    if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if SSL is enforced directly in the cluster parameters
      if (this.hasDirectSslEnforcement(resource)) {
        return null;
      }

      // Check if the cluster references a parameter group that enforces SSL
      if (allResources) {
        const paramGroupName = this.getResourceId(resource.Properties?.DBClusterParameterGroupName);

        if (paramGroupName) {
          const paramGroup = this.findDbClusterParameterGroupByName(paramGroupName, allResources);

          if (paramGroup && this.parameterGroupEnforcesSsl(paramGroup)) {
            return null;
          }
        }
      }

      // No SSL enforcement found
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Ensure the DB cluster parameter group sets 'rds.force_ssl' to true or 'ssl' to 1 to enforce SSL connections.`
      );
    }

    return null;
  }

  private hasDirectSslEnforcement(resource: CloudFormationResource): boolean {
    const parameters = resource.Properties?.Parameters;

    if (parameters) {
      // Check for common SSL enforcement parameters
      if (parameters['rds.force_ssl'] === true || parameters['ssl'] === '1') {
        return true;
      }
    }

    return false;
  }

  private findDbParameterGroupByName(name: string, allResources: CloudFormationResource[]): CloudFormationResource | null {
    return allResources.find(r =>
      r.Type === 'AWS::RDS::DBParameterGroup' &&
      (r.LogicalId === name || r.Properties?.DBParameterGroupName === name)
    ) || null;
  }

  private findDbClusterParameterGroupByName(name: string, allResources: CloudFormationResource[]): CloudFormationResource | null {
    return allResources.find(r =>
      r.Type === 'AWS::RDS::DBClusterParameterGroup' &&
      (r.LogicalId === name)// || r.Properties?.DBClusterParameterGroupName === name)
      //(r.LogicalId === name || r.Properties?.DBClusterParameterGroupName === name)
    ) || null;
  }

  private parameterGroupEnforcesSsl(paramGroup: CloudFormationResource): boolean {
    if (!paramGroup.Properties) {
      return false;
    }

    // Check for parameters that enforce SSL
    const parameters = paramGroup.Properties.Parameters;

    if (parameters) {
      // Check for common SSL enforcement parameters
      if (parameters['rds.force_ssl'] === true || parameters['ssl'] === '1') {
        return true;
      }
    }

    return false;
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

export default new Rds003Rule();
