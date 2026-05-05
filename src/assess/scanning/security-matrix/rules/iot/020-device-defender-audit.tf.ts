import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT020Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-020', 'HIGH', 'IoT deployment lacks Device Defender audit configuration', ['aws_iot_topic_rule']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_topic_rule') {
      const hasAuditConfig = allResources.some(r =>
        r.type === 'aws_iot_account_audit_configuration'
      );

      if (!hasAuditConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_iot_account_audit_configuration to enable Device Defender audits.');
      }
    }

    return null;
  }
}

export default new TfIoT020Rule();
