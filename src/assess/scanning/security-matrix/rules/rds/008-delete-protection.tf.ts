import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds008Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-008',
      'HIGH',
      'RDS Database does not have delete protection enabled',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.replicate_source_db) {
        return null;
      }

      if (resource.values?.deletion_protection !== true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set deletion_protection = true.'
        );
      }
    }

    if (resource.type === 'aws_rds_cluster') {
      if (resource.values?.deletion_protection !== true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set deletion_protection = true.'
        );
      }
    }

    return null;
  }
}

export default new TfRds008Rule();
