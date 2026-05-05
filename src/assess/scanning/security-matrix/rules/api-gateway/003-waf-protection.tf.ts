import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw003Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-003', 'HIGH', 'API Gateway stage does not have WAF protection enabled', ['aws_api_gateway_stage']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_stage') {
      const hasWafAssociation = allResources.some(r =>
        r.type === 'aws_wafv2_web_acl_association' &&
        r.values?.resource_arn?.includes(resource.values?.arn)
      );

      if (!hasWafAssociation) {
        return this.createScanResult(resource, projectName, this.description, 'Associate a WAFv2 Web ACL with this API Gateway stage using aws_wafv2_web_acl_association.');
      }
    }

    return null;
  }
}

export default new TfApigw003Rule();
