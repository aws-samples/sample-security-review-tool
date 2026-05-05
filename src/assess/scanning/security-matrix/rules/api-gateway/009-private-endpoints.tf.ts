import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw009Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-009', 'MEDIUM', 'API Gateway does not use private endpoints for internal APIs', ['aws_api_gateway_rest_api']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_rest_api') {
      const endpointConfig = resource.values?.endpoint_configuration;
      if (!endpointConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Add endpoint_configuration with types = ["PRIVATE"] for internal-only APIs.');
      }

      const types = endpointConfig.types;
      if (Array.isArray(types) && types.includes('EDGE')) {
        return this.createScanResult(resource, projectName, this.description, 'Consider using PRIVATE or REGIONAL endpoint type instead of EDGE for internal APIs.');
      }
    }

    return null;
  }
}

export default new TfApigw009Rule();
