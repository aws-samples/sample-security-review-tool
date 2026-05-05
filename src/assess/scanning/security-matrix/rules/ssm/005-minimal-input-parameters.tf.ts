import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSsm001Rule extends BaseTerraformRule {
  constructor() {
    super('SSM-001', 'HIGH', 'SSM Document has excessive number of input parameters', ['aws_ssm_document']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ssm_document') {
      const content = resource.values?.content;
      if (!content || typeof content !== 'string') return null;

      let parsed: any;
      try {
        parsed = JSON.parse(content);
      } catch {
        return null;
      }

      const parameters = parsed.parameters || {};
      const count = Object.keys(parameters).length;

      if (count > 10) {
        return this.createScanResult(resource, projectName, this.description + ' (' + count + ' parameters)', 'Reduce parameter count to 10 or fewer by consolidating related parameters.');
      }
    }

    return null;
  }
}

export default new TfSsm001Rule();
