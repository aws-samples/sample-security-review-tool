import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH6 Rule: Confirm that an off-peak window is configured at an appropriate time for service upgrades.
 */
export class ESH006Rule extends BaseRule {
  constructor() {
    super(
      'ESH-006',
      'HIGH',
      'OpenSearch domain missing off-peak window configuration',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const offPeakWindowOptions = resource.Properties?.OffPeakWindowOptions;

    if (!offPeakWindowOptions || !offPeakWindowOptions.Enabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure OffPeakWindowOptions with appropriate time window.`
      );
    }

    return null;
  }
}

export default new ESH006Rule();