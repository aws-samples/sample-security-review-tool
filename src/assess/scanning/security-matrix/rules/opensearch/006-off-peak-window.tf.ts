import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh006Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-006',
      'HIGH',
      'OpenSearch domain missing off-peak window configuration',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const offPeakWindowOptions = resource.values?.off_peak_window_options;

    if (!offPeakWindowOptions || offPeakWindowOptions.enabled !== true) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure off_peak_window_options with enabled = true and appropriate time window.`
      );
    }

    return null;
  }
}

export default new TfEsh006Rule();
