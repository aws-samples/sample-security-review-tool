import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfRds011Rule extends BaseTerraformRule {
  constructor() {
    super(
      'RDS-011',
      'HIGH',
      'RDS resources do not have event notifications enabled',
      ['aws_db_instance', 'aws_rds_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_db_instance' || resource.type === 'aws_rds_cluster') {
      const hasEventSubscription = allResources.some(r =>
        r.type === 'aws_db_event_subscription'
      );

      if (!hasEventSubscription) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Create an aws_db_event_subscription resource to enable RDS event notifications.'
        );
      }
    }

    return null;
  }
}

export default new TfRds011Rule();
