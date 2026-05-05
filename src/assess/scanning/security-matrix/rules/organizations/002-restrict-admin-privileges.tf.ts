import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfO002Rule extends BaseTerraformRule {
  constructor() {
    super('ORG-002', 'HIGH', 'IAM user has Organizations permissions or role lacks proper access constraints', ['aws_iam_user', 'aws_iam_role', 'aws_iam_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_iam_user') {
      const attachedPolicies = allResources.filter(r =>
        r.type === 'aws_iam_user_policy_attachment' &&
        r.values?.user === resource.values?.name
      );

      for (const attachment of attachedPolicies) {
        const policyArn = attachment.values?.policy_arn || '';
        if (policyArn.includes('Organizations')) {
          return this.createScanResult(resource, projectName, this.description, 'Remove Organizations permissions from IAM user. Use IAM roles with MFA conditions instead.');
        }
      }
    }

    return null;
  }
}

export default new TfO002Rule();
