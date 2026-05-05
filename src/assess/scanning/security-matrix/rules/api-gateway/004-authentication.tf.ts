import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw004Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-004', 'HIGH', 'API Gateway does not have authentication configured', ['aws_api_gateway_rest_api', 'aws_apigatewayv2_api']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_rest_api') {
      const hasAuthorizer = allResources.some(r =>
        r.type === 'aws_api_gateway_authorizer' &&
        r.values?.rest_api_id === resource.values?.id
      );

      if (!hasAuthorizer) {
        return this.createScanResult(resource, projectName, this.description, 'Add an aws_api_gateway_authorizer resource (Cognito, Lambda, or IAM) to protect API endpoints.');
      }
    }

    if (resource.type === 'aws_apigatewayv2_api') {
      const hasAuthorizer = allResources.some(r =>
        r.type === 'aws_apigatewayv2_authorizer' &&
        r.values?.api_id === resource.values?.id
      );

      if (!hasAuthorizer) {
        return this.createScanResult(resource, projectName, this.description, 'Add an aws_apigatewayv2_authorizer resource to protect API endpoints.');
      }
    }

    return null;
  }
}

export default new TfApigw004Rule();
