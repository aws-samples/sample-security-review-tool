import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH10 Rule: Ensure OpenSearch domain has restrictive access policies.
 */
export class ESH010Rule extends BaseRule {
  constructor() {
    super(
      'ESH-010',
      'HIGH',
      'OpenSearch domain has overly permissive access policies',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const accessPolicies = resource.Properties?.AccessPolicies;

    if (!accessPolicies) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} - Missing AccessPolicies`,
        `Define restrictive access policies.`
      );
    }

    // Check for overly permissive policies
    const statements = accessPolicies.Statement || [];
    const hasPermissivePolicy = statements.some((stmt: any) =>
      stmt.Effect === 'Allow' &&
      (stmt.Principal === '*' || stmt.Principal?.AWS === '*') &&
      stmt.Resource === '*'
    );

    if (hasPermissivePolicy) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description} - Access policy allows unrestricted access`,
        `Restrict Principal and Resource in access policies.`
      );
    }

    return null;
  }
}

export default new ESH010Rule();