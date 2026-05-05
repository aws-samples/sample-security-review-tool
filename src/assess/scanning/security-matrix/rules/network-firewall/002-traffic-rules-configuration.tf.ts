import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNetFw002Rule extends BaseTerraformRule {
  constructor() {
    super('NETFW-002', 'HIGH', 'Network Firewall policy does not have proper traffic filtering rules configured', ['aws_networkfirewall_firewall_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_networkfirewall_firewall_policy') {
      const firewallPolicy = resource.values?.firewall_policy;
      if (!firewallPolicy) {
        return this.createScanResult(resource, projectName, this.description, 'Add firewall_policy block with stateless and stateful rule group references.');
      }

      const statelessRuleGroupRefs = firewallPolicy.stateless_rule_group_reference;
      const statefulRuleGroupRefs = firewallPolicy.stateful_rule_group_reference;

      if ((!statelessRuleGroupRefs || statelessRuleGroupRefs.length === 0) &&
          (!statefulRuleGroupRefs || statefulRuleGroupRefs.length === 0)) {
        return this.createScanResult(resource, projectName, this.description, 'Add stateless_rule_group_reference or stateful_rule_group_reference to the firewall_policy block.');
      }
    }

    return null;
  }
}

export default new TfNetFw002Rule();
