import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH11 Rule: Enable node-to-node encryption for OpenSearch/Elasticsearch domains.
 */
export class ESH011Rule extends BaseRule {
  constructor() {
    super(
      'ESH-011',
      'HIGH',
      'OpenSearch domain node-to-node encryption not enabled',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const nodeToNodeEncryptionOptions = resource.Properties?.NodeToNodeEncryptionOptions;

    if (!nodeToNodeEncryptionOptions?.Enabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set NodeToNodeEncryptionOptions.Enabled to true.`
      );
    }

    return null;
  }
}

export default new ESH011Rule();