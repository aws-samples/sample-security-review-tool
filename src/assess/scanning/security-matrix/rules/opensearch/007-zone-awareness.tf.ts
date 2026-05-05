import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh007Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-007',
      'HIGH',
      'OpenSearch domain not configured for zone awareness',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const clusterConfig = resource.values?.cluster_config;

    if (!clusterConfig?.zone_awareness_enabled) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set zone_awareness_enabled to true in cluster_config.`
      );
    }

    const zoneAwarenessConfig = clusterConfig.zone_awareness_config;
    if (zoneAwarenessConfig) {
      const azCount = zoneAwarenessConfig.availability_zone_count;
      if (azCount && azCount < 2) {
        return this.createScanResult(
          resource,
          projectName,
          `${this.description} - availability_zone_count is ${azCount}`,
          `Set availability_zone_count to at least 2.`
        );
      }
    }

    return null;
  }
}

export default new TfEsh007Rule();
