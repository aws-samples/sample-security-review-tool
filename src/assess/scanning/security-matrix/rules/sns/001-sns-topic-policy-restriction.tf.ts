import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSns001Rule extends BaseTerraformRule {
  constructor() {
    super('SNS-001', 'HIGH', 'SNS topic policy allows wildcard principals without restrictive conditions, violating principle of least privilege', ['aws_sns_topic_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sns_topic_policy') {
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

      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const principal = stmt.Principal;
        const hasWildcard = principal === '*' || principal?.AWS === '*';

        if (hasWildcard && !this.hasRestrictiveConditions(stmt.Condition)) {
          return this.createScanResult(resource, projectName, this.description, 'Add restrictive Condition with aws:SourceArn, aws:SourceAccount, or aws:PrincipalOrgID.');
        }
      }
    }

    return null;
  }

  private hasRestrictiveConditions(conditions: any): boolean {
    if (!conditions) return false;
    const restrictiveKeys = ['aws:SourceArn', 'aws:SourceAccount', 'aws:PrincipalAccount', 'aws:PrincipalOrgID'];
    for (const operator of Object.keys(conditions)) {
      for (const key of restrictiveKeys) {
        if (conditions[operator]?.[key]) return true;
      }
    }
    return false;
  }
}

export default new TfSns001Rule();
