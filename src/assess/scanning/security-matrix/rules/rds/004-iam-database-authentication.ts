import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds004Rule extends BaseRule {
  constructor() {
    super(
      'RDS-004',
      'HIGH',
      'RDS database does not have IAM authentication enabled',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Check if the instance belongs to a cluster
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;

      // If the instance belongs to a cluster, skip checking it to avoid duplicate issues
      // as IAM authentication is configured at the cluster level for Aurora
      if (dbClusterIdentifier) {
        return null;
      }

      // Check if the engine is MySQL or PostgreSQL
      const engine = resource.Properties?.Engine;

      // Only proceed if engine is a string
      if (typeof engine === 'string') {
        // Check if the engine is MySQL or PostgreSQL
        if (engine.toLowerCase().includes('mysql') || engine.toLowerCase().includes('postgres')) {
          const iamAuthEnabled = resource.Properties?.EnableIAMDatabaseAuthentication;

          if (iamAuthEnabled !== true) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Set EnableIAMDatabaseAuthentication to true to enable IAM authentication for database access.`
            );
          }
        }
      }
    }

    if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if the engine is MySQL or PostgreSQL
      const engine = resource.Properties?.Engine;

      // Only proceed if engine is a string
      if (typeof engine === 'string') {
        // Check if the engine is MySQL or PostgreSQL
        if (engine.toLowerCase().includes('mysql') || engine.toLowerCase().includes('postgres')) {
          const iamAuthEnabled = resource.Properties?.EnableIAMDatabaseAuthentication;

          if (iamAuthEnabled !== true) {
            return this.createScanResult(
              resource,
              stackName,
              `${this.description}`,
              `Set EnableIAMDatabaseAuthentication to true to enable IAM authentication for database access at the cluster level.`
            );
          }
        }
      }
    }

    return null;
  }
}

export default new Rds004Rule();
