import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfKms007Rule extends BaseTerraformRule {
  constructor() {
    super('KMS-007', 'HIGH', 'KMS key deployed without monitoring infrastructure for events and compliance', ['aws_kms_key']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_kms_key') {
      const hasKmsEventRule = allResources.some(r =>
        r.type === 'aws_cloudwatch_event_rule' &&
        JSON.stringify(r.values?.event_pattern || '').includes('aws.kms')
      );

      const hasConfigRule = allResources.some(r =>
        r.type === 'aws_config_config_rule' &&
        (r.values?.source?.source_identifier || '').includes('kms')
      );

      if (!hasKmsEventRule && !hasConfigRule) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_cloudwatch_event_rule with event_pattern source "aws.kms" for KMS event monitoring.');
      }
    }

    return null;
  }
}

export default new TfKms007Rule();
