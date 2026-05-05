import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw006Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-006', 'HIGH', 'API Gateway stage does not have CloudWatch logging enabled', ['aws_api_gateway_stage']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_stage') {
      const hasMethodSettings = allResources.some(r =>
        r.type === 'aws_api_gateway_method_settings' &&
        r.values?.stage_name === resource.values?.stage_name &&
        r.values?.settings?.logging_level &&
        r.values.settings.logging_level !== 'OFF'
      );

      if (!hasMethodSettings) {
        return this.createScanResult(resource, projectName, this.description, 'Add aws_api_gateway_method_settings with settings { logging_level = "INFO" } to enable CloudWatch execution logging.');
      }
    }

    return null;
  }
}

export default new TfApigw006Rule();
