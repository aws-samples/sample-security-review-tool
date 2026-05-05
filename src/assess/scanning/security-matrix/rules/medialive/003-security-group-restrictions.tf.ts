import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfMediaLive003Rule extends BaseTerraformRule {
  constructor() {
    super('MEDIALIVE-003', 'HIGH', 'MediaLive input security group must have specific whitelist rules to restrict access', ['aws_medialive_input_security_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_medialive_input_security_group') {
      const whitelistRules = resource.values?.whitelist_rules;
      if (!whitelistRules || !Array.isArray(whitelistRules) || whitelistRules.length === 0) {
        return this.createScanResult(resource, projectName, this.description, 'Add whitelist_rules with specific CIDR blocks to restrict access.');
      }

      for (const rule of whitelistRules) {
        if (rule.cidr === '0.0.0.0/0') {
          return this.createScanResult(resource, projectName, this.description, 'Replace "0.0.0.0/0" with specific CIDR blocks.');
        }
      }
    }

    return null;
  }
}

export default new TfMediaLive003Rule();
