import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw005Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-005', 'MEDIUM', 'API Gateway does not use VPC PrivateLink for internal communication', ['aws_api_gateway_rest_api']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_rest_api') {
      const endpointConfig = resource.values?.endpoint_configuration;
      if (!endpointConfig) {
        return this.createScanResult(resource, projectName, this.description, 'Configure endpoint_configuration with types = ["PRIVATE"] for internal APIs.');
      }

      const types = endpointConfig.types;
      if (Array.isArray(types) && types.includes('PRIVATE')) {
        return null;
      }

      const hasVpcLink = allResources.some(r =>
        r.type === 'aws_api_gateway_vpc_link'
      );

      if (!hasVpcLink && Array.isArray(types) && !types.includes('PRIVATE')) {
        return this.createScanResult(resource, projectName, this.description, 'Use PRIVATE endpoint type or create an aws_api_gateway_vpc_link for VPC PrivateLink connectivity.');
      }
    }

    return null;
  }
}

export default new TfApigw005Rule();
