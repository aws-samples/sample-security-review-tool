import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds001Rule extends BaseRule {
  constructor() {
    super(
      'RDS-001',
      'HIGH',
      'RDS database not configured for multi-AZ deployment',
      ['AWS::RDS::DBCluster', 'AWS::RDS::DBInstance']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if the RDS cluster has multiple availability zones
      const availabilityZones = resource.Properties?.AvailabilityZones;

      if (!availabilityZones || !Array.isArray(availabilityZones) || availabilityZones.length < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Specify at least two AvailabilityZones for RDS clusters to ensure high availability and fault tolerance.`
        );
      }

      // Check if the cluster is Aurora Serverless, which handles multi-AZ automatically
      const engineMode = resource.Properties?.EngineMode;
      if (engineMode === 'serverless') {
        // Aurora Serverless handles multi-AZ automatically, so no issue
        return null;
      }

      // Check if the cluster has at least 2 instances for proper multi-AZ configuration
      // This applies to Aurora provisioned clusters
      const dbClusterInstanceCount = resource.Properties?.DBClusterInstanceCount;
      if (engineMode === 'provisioned' && (!dbClusterInstanceCount || dbClusterInstanceCount < 2)) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set DBClusterInstanceCount to at least 2 for Aurora provisioned clusters to ensure proper multi-AZ deployment.`
        );
      }
    }

    if (resource.Type === 'AWS::RDS::DBInstance') {
      // Skip instances that belong to a cluster as high availability is managed at the cluster level
      const dbClusterIdentifier = resource.Properties?.DBClusterIdentifier;
      if (dbClusterIdentifier) {
        return null;
      }

      // Check if the RDS instance has MultiAZ enabled
      const multiAZ = resource.Properties?.MultiAZ;
      if (multiAZ !== true) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set MultiAZ to true for RDS instances to ensure high availability and fault tolerance.`
        );
      }
    }

    return null;
  }
}

export default new Rds001Rule();
