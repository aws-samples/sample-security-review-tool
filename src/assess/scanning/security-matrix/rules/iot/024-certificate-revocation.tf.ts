import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIoT024Rule extends BaseTerraformRule {
  constructor() {
    super('IOT-024', 'HIGH', 'IoT deployment lacks certificate revocation mechanisms', ['aws_iot_certificate']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iot_certificate') {
      const hasAuditConfig = allResources.some(r =>
        r.type === 'aws_iot_account_audit_configuration'
      );

      if (!hasAuditConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_iot_account_audit_configuration to detect revoked certificates and implement certificate rotation.');
      }
    }

    return null;
  }
}

export default new TfIoT024Rule();
