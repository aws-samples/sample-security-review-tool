import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH8 Rule: Enable encryption of data at rest in the OpenSearch security configuration.
 */
export class ESH008Rule extends BaseRule {
  constructor() {
    super(
      'ESH-008',
      'HIGH',
      'OpenSearch domain encryption at rest not enabled',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const encryptionAtRestOptions = resource.Properties?.EncryptionAtRestOptions;

    if (!encryptionAtRestOptions?.Enabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EncryptionAtRestOptions.Enabled to true.`
      );
    }

    return null;
  }
}

export default new ESH008Rule();