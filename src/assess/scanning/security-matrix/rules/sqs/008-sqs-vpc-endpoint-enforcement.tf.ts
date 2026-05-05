import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSqs008Rule extends BaseTerraformRule {
  constructor() {
    super('SQS-008', 'HIGH', 'Consider adding VPC endpoint enforcement if this workload requires private network connectivity to SQS', ['aws_sqs_queue_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sqs_queue_policy') {
      const policy = resource.values?.policy;
      if (!policy) return null;

      const policyStr = typeof policy === 'string' ? policy : JSON.stringify(policy);

      const hasVpcConditions = policyStr.includes('aws:sourceVpce') || policyStr.includes('aws:SourceVpce');
      if (!hasVpcConditions) return null;

      const hasDenyVpcEnforcement = policyStr.includes('Deny') && hasVpcConditions;
      if (!hasDenyVpcEnforcement) {
        return this.createScanResult(resource, projectName, this.description, 'Add Deny statement with Condition StringNotEquals aws:sourceVpce to enforce VPC endpoint usage.');
      }
    }

    return null;
  }
}

export default new TfSqs008Rule();
