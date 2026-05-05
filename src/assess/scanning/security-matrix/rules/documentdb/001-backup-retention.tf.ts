import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDocdb001Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DOCDB-001',
      'HIGH',
      'DocumentDB cluster does not have a minimum backup retention period configured',
      ['aws_docdb_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const backupRetentionPeriod = resource.values?.backup_retention_period;

    if (backupRetentionPeriod === undefined || backupRetentionPeriod === null) {
      return null;
    }

    const retentionDays = Number(backupRetentionPeriod);

    if (isNaN(retentionDays)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set backup_retention_period to a valid numeric value between 1 and 35 days.`
      );
    }

    if (retentionDays === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Enable automated backups by setting backup_retention_period to a value between 1 and 35 days.`
      );
    }

    if (retentionDays < 1 || retentionDays > 35) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set backup_retention_period to a value between 1 and 35 days (current value: ${retentionDays} days).`
      );
    }

    return null;
  }
}

export default new TfDocdb001Rule();
