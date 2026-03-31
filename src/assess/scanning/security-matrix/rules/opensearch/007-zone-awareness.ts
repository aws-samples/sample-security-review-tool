import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH7 Rule: Activate cross-zone replication (Zone Awareness) to have multi-zone availability.
 */
export class ESH007Rule extends BaseRule {
  constructor() {
    super(
      'ESH-007',
      'HIGH',
      'OpenSearch domain not configured for zone awareness',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const clusterConfig = resource.Properties?.ClusterConfig;

    if (!clusterConfig?.ZoneAwarenessEnabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set ZoneAwarenessEnabled to true in ClusterConfig.`
      );
    }

    // Check for proper zone awareness configuration
    if (clusterConfig.ZoneAwarenessEnabled && clusterConfig.ZoneAwarenessConfig) {
      const availabilityZoneCount = clusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount;
      if (availabilityZoneCount && availabilityZoneCount < 2) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description} - AvailabilityZoneCount is ${availabilityZoneCount}`,
          `Set AvailabilityZoneCount to at least 2.`
        );
      }
    }

    return null;
  }
}

export default new ESH007Rule();