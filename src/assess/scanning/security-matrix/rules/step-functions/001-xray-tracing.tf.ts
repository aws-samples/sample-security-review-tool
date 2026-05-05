import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfStepFunctions001Rule extends BaseTerraformRule {
  constructor() {
    super('SF-002', 'MEDIUM', 'Step Function lacks X-Ray tracing for service integrations', ['aws_sfn_state_machine']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sfn_state_machine') {
      const tracingConfig = resource.values?.tracing_configuration;
      if (!tracingConfig || tracingConfig.enabled !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Add tracing_configuration { enabled = true } to enable X-Ray tracing.');
      }
    }

    return null;
  }
}

export default new TfStepFunctions001Rule();
