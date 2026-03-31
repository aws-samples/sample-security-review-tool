import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds002Rule extends BaseRule {
  constructor() {
    super(
      'RDS-002',
      'HIGH',
      'Database does not have encryption at rest enabled',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Check if the instance belongs to a cluster
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;

      // If the instance belongs to a cluster, skip checking it to avoid duplicate issues
      // as encryption is configured at the cluster level for Aurora
      if (dbClusterIdentifier) {
        return null;
      }

      const storageEncrypted = resource.Properties?.StorageEncrypted;

      if (storageEncrypted !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set StorageEncrypted to true to enable encryption at rest.`
        );
      }
    }

    if (resource.Type === 'AWS::RDS::DBCluster') {
      const storageEncrypted = resource.Properties?.StorageEncrypted;

      if (storageEncrypted !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set StorageEncrypted to true to enable encryption at rest for the DB cluster.`
        );
      }
    }

    return null;
  }
}

export default new Rds002Rule();
