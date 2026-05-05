import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH4 Rule: Deploy OpenSearch Service using dedicated master nodes.
 */
export class ESH004Rule extends BaseRule {
  constructor() {
    super(
      'ESH-004',
      'HIGH',
      'OpenSearch domain not using dedicated master nodes',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const clusterConfig = resource.Properties?.ClusterConfig;

    if (!clusterConfig?.DedicatedMasterEnabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set DedicatedMasterEnabled to true and configure MasterInstanceType, MasterInstanceCount in ClusterConfig.`
      );
    }

    // Check if master node configuration is adequate
    if (clusterConfig.DedicatedMasterEnabled && !clusterConfig.MasterInstanceCount) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} - Missing MasterInstanceCount`,
        `Set MasterInstanceCount to at least 3 for production.`
      );
    }

    return null;
  }
}

export default new ESH004Rule();