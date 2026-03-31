import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH12 Rule: Enable encryption in transit (HTTPS) for OpenSearch/Elasticsearch domains.
 */
export class ESH012Rule extends BaseRule {
  constructor() {
    super(
      'ESH-012',
      'HIGH',
      'OpenSearch domain encryption in transit not enabled',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const domainEndpointOptions = resource.Properties?.DomainEndpointOptions;

    if (!domainEndpointOptions?.EnforceHTTPS) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set DomainEndpointOptions.EnforceHTTPS to true.`
      );
    }

    return null;
  }
}

export default new ESH012Rule();