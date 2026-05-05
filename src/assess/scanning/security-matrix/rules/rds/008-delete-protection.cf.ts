import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds008Rule extends BaseRule {
  constructor() {
    super(
      'RDS-008',
      'HIGH',
      'RDS Database does not have delete protection enabled',
      ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this is an RDS instance
    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Skip DB instances that belong to a DB cluster (they inherit the cluster's delete protection)
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;
      if (dbClusterIdentifier) {
        return null;
      }

      // Check if DeletionProtection is explicitly set to false or not set at all
      const deletionProtection = resource.Properties?.DeletionProtection;

      if (deletionProtection !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set DeletionProtection to true.`
        );
      }
    }
    // Check if this is an RDS cluster
    else if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if DeletionProtection is explicitly set to false or not set at all
      const deletionProtection = resource.Properties?.DeletionProtection;

      if (deletionProtection !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set DeletionProtection to true.`
        );
      }
    }

    return null;
  }
}

export default new Rds008Rule();
