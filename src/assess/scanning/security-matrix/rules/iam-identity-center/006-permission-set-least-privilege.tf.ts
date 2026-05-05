import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfIdC006Rule extends BaseTerraformRule {
  constructor() {
    super('IdC-006', 'HIGH', 'Identity Center permission set violates least privilege principle', ['aws_ssoadmin_permission_set']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_ssoadmin_permission_set') {
      const sessionDuration = resource.values?.session_duration;
      if (sessionDuration && this.exceedsMaxDuration(sessionDuration)) {
        return this.createScanResult(resource, projectName, this.description, 'Set session_duration to "PT8H" or less.');
      }

      const managedPolicies = allResources.filter(r =>
        r.type === 'aws_ssoadmin_managed_policy_attachment' &&
        r.values?.permission_set_arn === resource.values?.arn
      );

      const dangerousPatterns = ['AdministratorAccess', 'PowerUserAccess', 'FullAccess'];
      for (const mp of managedPolicies) {
        const policyArn = mp.values?.managed_policy_arn || '';
        if (dangerousPatterns.some(p => policyArn.includes(p))) {
          return this.createScanResult(resource, projectName, this.description, 'Replace overly broad managed policies with specific least-privilege policies.');
        }
      }
    }

    return null;
  }

  private exceedsMaxDuration(duration: string): boolean {
    const match = duration.match(/^PT(\d+)H$/);
    if (!match) return true;
    return parseInt(match[1], 10) > 8;
  }
}

export default new TfIdC006Rule();
