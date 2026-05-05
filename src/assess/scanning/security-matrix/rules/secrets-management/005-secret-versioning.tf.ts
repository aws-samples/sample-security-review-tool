import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSec005Rule extends BaseTerraformRule {
  constructor() {
    super('SEC-005', 'MEDIUM', 'Secret lacks documentation of purpose and ownership', ['aws_secretsmanager_secret']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_secretsmanager_secret') {
      const description = resource.values?.description;
      if (!description) {
        return this.createScanResult(resource, projectName, 'Secret lacks a description', 'Add a description to document the purpose of the secret.');
      }

      if (typeof description === 'string' && description.length < 10) {
        return this.createScanResult(resource, projectName, 'Secret has a very short description', 'Provide a more detailed description explaining the purpose and ownership.');
      }
    }

    return null;
  }
}

export default new TfSec005Rule();
