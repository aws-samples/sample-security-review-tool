import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfNetSg002Rule extends BaseTerraformRule {
  constructor() {
    super('NET-SG-002', 'HIGH', 'Security group allows overly broad egress access. Action: Restrict egress rules to specific CIDR ranges or ports that are required for your application.', ['aws_security_group']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    // This rule defers to other EC2 security group rules for egress checks
    return null;
  }
}

export default new TfNetSg002Rule();
