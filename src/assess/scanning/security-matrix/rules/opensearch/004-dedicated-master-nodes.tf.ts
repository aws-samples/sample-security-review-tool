import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-004',
      'HIGH',
      'OpenSearch domain not using dedicated master nodes',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const clusterConfig = resource.values?.cluster_config;

    if (!clusterConfig?.dedicated_master_enabled) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set dedicated_master_enabled to true and configure dedicated_master_type and dedicated_master_count in cluster_config.`
      );
    }

    if (clusterConfig.dedicated_master_enabled && !clusterConfig.dedicated_master_count) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} - Missing dedicated_master_count`,
        `Set dedicated_master_count to at least 3 for production.`
      );
    }

    return null;
  }
}

export default new TfEsh004Rule();
