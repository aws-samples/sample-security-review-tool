import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSec004Rule extends BaseTerraformRule {
  constructor() {
    super('SEC-004', 'HIGH', 'Secret has overly permissive access policy', ['aws_secretsmanager_secret_policy']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_secretsmanager_secret_policy') {
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
        if (principal === '*' || principal?.AWS === '*') {
          return this.createScanResult(resource, projectName, this.description, 'Restrict the resource policy to specific principals and avoid using wildcards.');
        }
      }
    }

    return null;
  }
}

export default new TfSec004Rule();
