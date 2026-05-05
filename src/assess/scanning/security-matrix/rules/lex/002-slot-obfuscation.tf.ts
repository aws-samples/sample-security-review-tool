import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLex002Rule extends BaseTerraformRule {
  constructor() {
    super('LEX-002', 'HIGH', 'Amazon Lex V2 bot contains slots with obfuscation explicitly disabled', ['aws_lexv2models_bot', 'aws_lex_bot']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_lexv2models_bot' || resource.type === 'aws_lex_bot') {
      const slotTypes = allResources.filter(r =>
        r.type === 'aws_lexv2models_slot' ||
        r.type === 'aws_lex_slot_type'
      );

      for (const slot of slotTypes) {
        const obfuscationSetting = slot.values?.obfuscation_setting;
        if (obfuscationSetting === 'NONE' || obfuscationSetting?.obfuscation_setting_type === 'None') {
          return this.createScanResult(resource, projectName, this.description, 'Remove obfuscation_setting or set obfuscation_setting_type to "DefaultObfuscation".');
        }
      }
    }

    return null;
  }
}

export default new TfLex002Rule();
