import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh011Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-011',
      'HIGH',
      'OpenSearch domain node-to-node encryption not enabled',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const nodeToNodeEncryption = resource.values?.node_to_node_encryption;

    if (!nodeToNodeEncryption?.enabled) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set node_to_node_encryption { enabled = true } to enable node-to-node encryption.`
      );
    }

    return null;
  }
}

export default new TfEsh011Rule();
