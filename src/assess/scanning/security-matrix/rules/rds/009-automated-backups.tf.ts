import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds009Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-009',
      'HIGH',
      'RDS Database does not have automated backups enabled for point-in-time recovery',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      const backupRetentionPeriod = resource.values?.backup_retention_period;
      if (backupRetentionPeriod === undefined || backupRetentionPeriod === 0) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set backup_retention_period to a value greater than 0.'
        );
      }
    }

    if (resource.type === 'aws_rds_cluster') {
      const backupRetentionPeriod = resource.values?.backup_retention_period;
      if (backupRetentionPeriod === undefined || backupRetentionPeriod === 0) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set backup_retention_period to a value greater than 0.'
        );
      }
    }

    return null;
  }
}

export default new TfRds009Rule();
