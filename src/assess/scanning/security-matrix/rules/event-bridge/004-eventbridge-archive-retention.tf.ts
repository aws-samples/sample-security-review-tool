import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEvb004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EVB-004',
      'HIGH',
      'EventBridge archive does not have a finite retention period configured. Events should not be kept in the archive for longer than necessary',
      ['aws_cloudwatch_event_archive']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const retentionDays = resource.values?.retention_days;

    if (!retentionDays || retentionDays === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Set retention_days to a finite value (e.g., 30)'
      );
    }

    return null;
  }
}

export default new TfEvb004Rule();
