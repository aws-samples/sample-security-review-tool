import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSsm002Rule extends BaseTerraformRule {
  constructor() {
    super('SSM-002', 'HIGH', 'SSM Automation Document parameter lacks validation constraints', ['aws_ssm_document']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ssm_document') {
      const documentType = resource.values?.document_type;
      if (documentType !== 'Automation') return null;

      const content = resource.values?.content;
      if (!content || typeof content !== 'string') return null;

      let parsed: any;
      try {
        parsed = JSON.parse(content);
      } catch {
        return null;
      }

      const parameters = parsed.parameters || {};
      for (const [paramName, paramConfig] of Object.entries(parameters)) {
        if (typeof paramConfig !== 'object' || paramConfig === null) continue;
        const config = paramConfig as any;
        if (config.type === 'Boolean' || config.default !== undefined) continue;

        if (!config.allowedPattern && !config.allowedValues) {
          return this.createScanResult(resource, projectName, this.description + ' (parameter: ' + paramName + ')', 'Add allowedPattern or allowedValues to parameter "' + paramName + '".');
        }
      }
    }

    return null;
  }
}

export default new TfSsm002Rule();
