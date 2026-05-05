import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh008Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-008',
      'HIGH',
      'OpenSearch domain encryption at rest not enabled',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const encryptAtRest = resource.values?.encrypt_at_rest;

    if (!encryptAtRest?.enabled) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set encrypt_at_rest { enabled = true } to enable encryption at rest.`
      );
    }

    return null;
  }
}

export default new TfEsh008Rule();
