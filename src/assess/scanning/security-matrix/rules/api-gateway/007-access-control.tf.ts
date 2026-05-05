import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw007Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-007', 'HIGH', 'API Gateway does not have proper access control configured', ['aws_api_gateway_rest_api']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_rest_api') {
      const policy = resource.values?.policy;
      if (!policy) {
        const hasAuthorizer = allResources.some(r =>
          r.type === 'aws_api_gateway_authorizer' &&
          r.values?.rest_api_id === resource.values?.id
        );

        if (!hasAuthorizer) {
          return this.createScanResult(resource, projectName, this.description, 'Add a resource policy or authorizer to restrict access to the API.');
        }
      }
    }

    return null;
  }
}

export default new TfApigw007Rule();
