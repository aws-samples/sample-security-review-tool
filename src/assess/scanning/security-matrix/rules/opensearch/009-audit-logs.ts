import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

/**
 * ESH9 Rule: Enable audit logs, configure an access policy, turn on audit logs in dashboards.
 */
export class ESH009Rule extends BaseRule {
  constructor() {
    super(
      'ESH-009',
      'HIGH',
      'OpenSearch domain audit logging not configured',
      ['AWS::OpenSearchService::Domain']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (!this.applicableResourceTypes.includes(resource.Type)) {
      return null;
    }

    const logPublishingOptions = resource.Properties?.LogPublishingOptions;
    const auditLogsEnabled = logPublishingOptions?.AUDIT_LOGS?.Enabled;

    // Check for audit logs enabled
    if (!auditLogsEnabled) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable AUDIT_LOGS in LogPublishingOptions.`
      );
    }

    // Check for access policies configured
    const accessPolicies = resource.Properties?.AccessPolicies;
    if (!accessPolicies) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure AccessPolicies to control audit log access.`
      );
    }

    // If it's a string, try to parse it as JSON
    if (typeof accessPolicies === 'string') {
      try {
        // Try to parse if it's a stringified JSON
        const parsedPolicy = JSON.parse(accessPolicies);
        // Check if the policy is empty or missing essential elements
        if (!parsedPolicy || !parsedPolicy.Statement || parsedPolicy.Statement.length === 0) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `AccessPolicies is empty or missing statements.`
          );
        }
      } catch (e) {
        // If we can't parse it, we can't verify its contents
        // This might be a parameter reference or intrinsic function
        // We won't fail it just because we can't parse it
      }
    } else if (typeof accessPolicies === 'object') {
      // Check if the policy object is empty or missing essential elements
      if (!accessPolicies.Statement || accessPolicies.Statement.length === 0) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `AccessPolicies is empty or missing statements.`
        );
      }
    }

    // Note: Dashboard audit log settings cannot be verified through CloudFormation
    // as they are typically configured at runtime or through APIs.

    return null;
  }
}

export default new ESH009Rule();
