import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLex001Rule extends BaseTerraformRule {
  constructor() {
    super('LEX-001', 'HIGH', 'Amazon Lex bot does not have DataPrivacy.ChildDirected set to true for COPPA compliance', ['aws_lexv2models_bot', 'aws_lex_bot']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_lexv2models_bot') {
      const childDirected = resource.values?.data_privacy?.child_directed;
      if (childDirected !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Set data_privacy { child_directed = true } to comply with COPPA.');
      }
    }

    if (resource.type === 'aws_lex_bot') {
      const childDirected = resource.values?.child_directed;
      if (childDirected !== true) {
        return this.createScanResult(resource, projectName, this.description, 'Set child_directed = true to comply with COPPA.');
      }
    }

    return null;
  }
}

export default new TfLex001Rule();
