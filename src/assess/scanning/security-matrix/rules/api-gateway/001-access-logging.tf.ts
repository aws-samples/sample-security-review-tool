import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw001Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-001', 'HIGH', 'API Gateway does not have access logging enabled with proper retention', ['aws_api_gateway_stage', 'aws_apigatewayv2_stage']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_stage') {
      const accessLogSettings = resource.values?.access_log_settings;
      if (!accessLogSettings || !accessLogSettings.destination_arn) {
        return this.createScanResult(resource, projectName, this.description, 'Configure access_log_settings with a destination_arn pointing to a CloudWatch log group.');
      }
    }

    if (resource.type === 'aws_apigatewayv2_stage') {
      const accessLogSettings = resource.values?.access_log_settings;
      if (!accessLogSettings || !accessLogSettings.destination_arn) {
        return this.createScanResult(resource, projectName, this.description, 'Configure access_log_settings with a destination_arn pointing to a CloudWatch log group.');
      }
    }

    return null;
  }
}

export default new TfApigw001Rule();
