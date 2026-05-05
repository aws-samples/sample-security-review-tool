import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEvb003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'EVB-003',
      'HIGH',
      'EventBus policy allows wildcard principals without restrictive conditions, violating principle of least privilege',
      ['aws_cloudwatch_event_bus_policy']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const policy = resource.values?.policy;
    if (!policy) return null;

    let policyDoc: any;
    try {
      policyDoc = typeof policy === 'string' ? JSON.parse(policy) : policy;
    } catch {
      return null;
    }

    const statements = policyDoc?.Statement;
    if (!Array.isArray(statements)) return null;

    for (const stmt of statements) {
      if (this.hasWildcardPrincipal(stmt) && !this.hasSecurityConditions(stmt.Condition)) {
        return this.createScanResult(
          resource,
          projectName,
          this.description,
          'Add restrictive Condition: { "StringEquals": { "aws:PrincipalAccount": "ACCOUNT_ID" } }'
        );
      }
    }

    return null;
  }

  private hasWildcardPrincipal(statement: any): boolean {
    if (!statement?.Principal) return false;

    if (statement.Principal === '*' || statement.Principal.AWS === '*') return true;

    if (statement.Principal.AWS) {
      const principals = Array.isArray(statement.Principal.AWS) ? statement.Principal.AWS : [statement.Principal.AWS];
      return principals.some((p: string) => typeof p === 'string' && p.includes('*'));
    }

    return false;
  }

  private hasSecurityConditions(conditions: any): boolean {
    if (!conditions) return false;

    const restrictiveKeys = [
      'aws:SourceArn', 'aws:SourceAccount', 'aws:PrincipalAccount',
      'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths', 'aws:SourceIp',
      'aws:RequestedRegion', 'events:source'
    ];

    for (const operator of Object.keys(conditions)) {
      for (const key of restrictiveKeys) {
        if (conditions[operator][key]) return true;
      }
    }

    return false;
  }
}

export default new TfEvb003Rule();
