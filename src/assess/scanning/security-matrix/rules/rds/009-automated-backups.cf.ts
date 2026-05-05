import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds009Rule extends BaseRule {
  constructor() {
    super(
      'RDS-009',
      'HIGH',
      'RDS Database does not have automated backups enabled for point-in-time recovery',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an RDS instance
    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Skip DB instances that belong to a DB cluster (they inherit the cluster's backup settings)
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;
      if (dbClusterIdentifier) {
        return null;
      }

      // Check if BackupRetentionPeriod is set and greater than 0
      const backupRetentionPeriod = resource.Properties?.BackupRetentionPeriod;

      if (backupRetentionPeriod === undefined || backupRetentionPeriod === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set BackupRetentionPeriod to a value greater than 0.`
        );
      }
    }
    // Check if this is an RDS cluster
    else if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if BackupRetentionPeriod is set and greater than 0
      const backupRetentionPeriod = resource.Properties?.BackupRetentionPeriod;

      if (backupRetentionPeriod === undefined || backupRetentionPeriod === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set BackupRetentionPeriod to a value greater than 0.`
        );
      }
    }

    return null;
  }
}

export default new Rds009Rule();
