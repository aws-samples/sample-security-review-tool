import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw002Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-002', 'HIGH', 'API Gateway does not have request validation enabled', ['aws_api_gateway_rest_api']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_rest_api') {
      const validators = allResources.filter(r =>
        r.type === 'aws_api_gateway_request_validator' &&
        r.values?.rest_api_id === resource.values?.id
      );

      if (validators.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Add an aws_api_gateway_request_validator resource to enable request validation.');
      }
    }

    return null;
  }
}

export default new TfApigw002Rule();
