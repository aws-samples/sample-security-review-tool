import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds010Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-010',
      'HIGH',
      'RDS Aurora Cluster does not have Backtrack enabled',
      ['aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_rds_cluster') {
      const backtrackWindow = resource.values?.backtrack_window;
      if (backtrackWindow === undefined || backtrackWindow <= 0) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set backtrack_window to a value greater than 0 to enable point-in-time recovery.'
        );
      }
    }

    return null;
  }
}

export default new TfRds010Rule();
