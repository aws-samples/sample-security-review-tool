import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfKms002Rule extends BaseTerraformRule {
  constructor() {
    super('KMS-002', 'HIGH', 'KMS key policy grants overly permissive access', ['aws_kms_key']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_kms_key') {
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

        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        const principal = stmt.Principal;

        const isRootPrincipal = this.isRootAccountPrincipal(principal);
        if (isRootPrincipal && actions.length === 1 && actions[0] === 'kms:*') continue;

        const hasWildcardAction = actions.some((a: string) => a === 'kms:*' || a === '*');
        if (hasWildcardAction) {
          return this.createScanResult(resource, projectName, this.description, 'Replace wildcard kms:* actions with specific KMS actions based on the use case.');
        }

        if (principal === '*' || principal?.AWS === '*') {
          return this.createScanResult(resource, projectName, this.description, 'Replace wildcard principal with specific IAM role or user ARNs.');
        }
      }
    }

    return null;
  }

  private isRootAccountPrincipal(principal: any): boolean {
    if (!principal) return false;
    const rootPattern = /^arn:aws:iam::\d{12}:root$/;
    if (typeof principal.AWS === 'string') return rootPattern.test(principal.AWS);
    if (Array.isArray(principal.AWS) && principal.AWS.length === 1) return rootPattern.test(principal.AWS[0]);
    return false;
  }
}

export default new TfKms002Rule();
