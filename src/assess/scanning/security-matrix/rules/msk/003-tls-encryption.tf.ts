import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMsk003Rule extends BaseTerraformRule {
  constructor() {
    super('MSK-003', 'HIGH', 'MSK cluster is not configured with TLS encryption between brokers', ['aws_msk_cluster']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_msk_cluster') {
      const inCluster = resource.values?.encryption_info?.[0]?.encryption_in_transit?.[0]?.in_cluster
        ?? resource.values?.encryption_info?.encryption_in_transit?.in_cluster;

      if (inCluster === false) {
        return this.createScanResult(resource, projectName, this.description, 'Set encryption_info.encryption_in_transit.in_cluster to true to enable TLS encryption between brokers.');
      }
    }

    return null;
  }
}

export default new TfMsk003Rule();
