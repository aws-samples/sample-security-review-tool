import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh010Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-010',
      'HIGH',
      'OpenSearch domain has overly permissive access policies',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const accessPolicies = resource.values?.access_policies;

    if (!accessPolicies) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} - Missing access_policies`,
        `Define restrictive access policies.`
      );
    }

    let policy: any = accessPolicies;
    if (typeof accessPolicies === 'string') {
      try {
        policy = JSON.parse(accessPolicies);
      } catch {
        return null;
      }
    }

    const statements = policy.Statement || [];
    const hasPermissivePolicy = statements.some((stmt: any) =>
      stmt.Effect === 'Allow' &&
      (stmt.Principal === '*' || stmt.Principal?.AWS === '*') &&
      stmt.Resource === '*'
    );

    if (hasPermissivePolicy) {
      return this.createScanResult(
        resource,
        projectName,
        `${this.description} - Access policy allows unrestricted access`,
        `Restrict Principal and Resource in access policies.`
      );
    }

    return null;
  }
}

export default new TfEsh010Rule();
