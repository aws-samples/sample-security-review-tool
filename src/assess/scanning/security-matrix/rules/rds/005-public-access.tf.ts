import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds005Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-005',
      'HIGH',
      'Database has public access enabled',
      ['aws_db_instance']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance') {
      if (resource.values?.publicly_accessible === true) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Set publicly_accessible = false and deploy in a private subnet.'
        );
      }
    }

    return null;
  }
}

export default new TfRds005Rule();
