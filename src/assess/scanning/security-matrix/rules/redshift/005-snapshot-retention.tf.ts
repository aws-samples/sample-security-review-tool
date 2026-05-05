import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRedshift005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'REDSHIFT-005',
      'HIGH',
      'Redshift cluster does not have automated snapshot retention configured',
      ['aws_redshift_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const retentionPeriod = resource.values?.automated_snapshot_retention_period;

    if (retentionPeriod === undefined || retentionPeriod === null) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Explicitly set automated_snapshot_retention_period to a value between 1 and 35 days (recommended: 7 days or more for production workloads).`
      );
    }

    const retentionDays = Number(retentionPeriod);

    if (isNaN(retentionDays)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set automated_snapshot_retention_period to a valid numeric value between 1 and 35 days.`
      );
    }

    if (retentionDays === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Enable automated snapshots by setting automated_snapshot_retention_period to a value between 1 and 35 days.`
      );
    }

    if (retentionDays < 1 || retentionDays > 35) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set automated_snapshot_retention_period to a value between 1 and 35 days (current value: ${retentionDays} days).`
      );
    }

    return null;
  }
}

export default new TfRedshift005Rule();
