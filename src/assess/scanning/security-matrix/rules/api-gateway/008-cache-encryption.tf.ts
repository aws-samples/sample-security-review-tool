import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfApigw008Rule extends BaseTerraformRule {
  constructor() {
    super('API-GW-008', 'HIGH', 'API Gateway stage cache does not have encryption enabled', ['aws_api_gateway_stage']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_api_gateway_stage') {
      const cacheClusterEnabled = resource.values?.cache_cluster_enabled;
      if (cacheClusterEnabled === true) {
        const methodSettings = allResources.filter(r =>
          r.type === 'aws_api_gateway_method_settings' &&
          r.values?.stage_name === resource.values?.stage_name
        );

        const hasCacheEncryption = methodSettings.some(ms =>
          ms.values?.settings?.cache_data_encrypted === true
        );

        if (!hasCacheEncryption) {
          return this.createScanResult(resource, projectName, this.description, 'Add aws_api_gateway_method_settings with settings { cache_data_encrypted = true } to encrypt cached data.');
        }
      }
    }

    return null;
  }
}

export default new TfApigw008Rule();
