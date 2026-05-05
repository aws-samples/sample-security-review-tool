import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh012Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-012',
      'HIGH',
      'OpenSearch domain encryption in transit not enabled',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const domainEndpointOptions = resource.values?.domain_endpoint_options;

    if (!domainEndpointOptions?.enforce_https) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set domain_endpoint_options { enforce_https = true } to enable encryption in transit.`
      );
    }

    return null;
  }
}

export default new TfEsh012Rule();
