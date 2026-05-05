import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-002',
      'HIGH',
      'Database does not have encryption at rest enabled',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      if (resource.values?.storage_encrypted !== true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set storage_encrypted = true to enable encryption at rest.'
        );
      }
    }

    if (resource.type === 'aws_rds_cluster') {
      if (resource.values?.storage_encrypted !== true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set storage_encrypted = true to enable encryption at rest for the DB cluster.'
        );
      }
    }

    return null;
  }
}

export default new TfRds002Rule();
