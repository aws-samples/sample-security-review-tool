import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Rds010Rule extends BaseRule {
  constructor() {
    super(
      'RDS-010',
      'HIGH',
      'RDS Aurora Cluster does not have Backtrack enabled',
      ['AWS::RDS::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (resource.Type === 'AWS::RDS::DBCluster') {
      // Check if BacktrackWindow is set and greater than 0
      const backtrackWindow = resource.Properties?.BacktrackWindow;
      if (backtrackWindow === undefined || backtrackWindow <= 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set BacktrackWindow to a value greater than 0 to enable point-in-time recovery.`
        );
      }
    }

    return null;
  }
}

export default new Rds010Rule();
