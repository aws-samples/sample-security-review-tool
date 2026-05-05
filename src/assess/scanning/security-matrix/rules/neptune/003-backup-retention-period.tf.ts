import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNeptune003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'NEPTUNE-003',
      'HIGH',
      'Neptune cluster does not have a minimum backup retention period of 7 days configured',
      ['aws_neptune_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const backupRetentionPeriod = resource.values?.backup_retention_period;

    if (backupRetentionPeriod === undefined || backupRetentionPeriod === null) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set backup_retention_period to at least 7 days to ensure adequate data recovery capabilities.`
      );
    }

    if (typeof backupRetentionPeriod === 'number' && backupRetentionPeriod < 7) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Increase backup_retention_period to at least 7 days (currently set to ${backupRetentionPeriod}).`
      );
    }

    return null;
  }
}

export default new TfNeptune003Rule();
