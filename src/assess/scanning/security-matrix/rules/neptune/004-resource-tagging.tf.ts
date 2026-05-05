import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNeptune004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'NEPTUNE-004',
      'MEDIUM',
      'Neptune cluster is missing required tags',
      ['aws_neptune_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const tags = resource.values?.tags;

    if (!tags || (typeof tags === 'object' && Object.keys(tags).length === 0)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add appropriate tags to Neptune clusters for better resource management, cost allocation, and security tracking.`
      );
    }

    return null;
  }
}

export default new TfNeptune004Rule();
