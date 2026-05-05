import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSqs007Rule extends BaseTerraformRule {
  constructor() {
    super('SQS-007', 'HIGH', 'SQS policy grants both administrative and usage permissions to the same principal, violating principle of least privilege', ['aws_sqs_queue_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sqs_queue_policy') {
      const policy = resource.values?.policy;
      if (!policy) return null;

      let policyObj: any;
      if (typeof policy === 'string') {
        try {
          policyObj = JSON.parse(policy);
        } catch {
          return null;
        }
      } else {
        policyObj = policy;
      }

      if (!policyObj?.Statement) return null;
      const statements = Array.isArray(policyObj.Statement) ? policyObj.Statement : [policyObj.Statement];

      const adminActions = ['sqs:CreateQueue', 'sqs:DeleteQueue', 'sqs:SetQueueAttributes', 'sqs:PurgeQueue', 'sqs:AddPermission', 'sqs:RemovePermission'];
      const usageActions = ['sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage'];

      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        const hasAdmin = actions.some((a: string) => adminActions.includes(a) || a === 'sqs:*');
        const hasUsage = actions.some((a: string) => usageActions.includes(a) || a === 'sqs:*');

        if (hasAdmin && hasUsage) {
          return this.createScanResult(resource, projectName, this.description, 'Separate admin actions from usage actions into different policy statements.');
        }
      }
    }

    return null;
  }
}

export default new TfSqs007Rule();
