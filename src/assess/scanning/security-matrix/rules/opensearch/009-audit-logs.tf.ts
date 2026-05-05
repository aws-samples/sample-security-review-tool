import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfEsh009Rule extends BaseTerraformRule {
  constructor() {
    super(
      'ESH-009',
      'HIGH',
      'OpenSearch domain audit logging not configured',
      ['aws_opensearch_domain']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const logPublishingOptions = resource.values?.log_publishing_options;

    if (!logPublishingOptions) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Enable AUDIT_LOGS in log_publishing_options.`
      );
    }

    const hasAuditLogs = this.hasAuditLogPublishing(logPublishingOptions);

    if (!hasAuditLogs) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Enable AUDIT_LOGS in log_publishing_options.`
      );
    }

    const accessPolicies = resource.values?.access_policies;
    if (!accessPolicies) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure access_policies to control audit log access.`
      );
    }

    return null;
  }

  private hasAuditLogPublishing(logPublishingOptions: any): boolean {
    if (Array.isArray(logPublishingOptions)) {
      return logPublishingOptions.some(
        (opt: any) => opt.log_type === 'AUDIT_LOGS' && opt.enabled !== false
      );
    }

    if (typeof logPublishingOptions === 'object') {
      if (logPublishingOptions.AUDIT_LOGS) {
        return logPublishingOptions.AUDIT_LOGS.enabled !== false;
      }
    }

    return false;
  }
}

export default new TfEsh009Rule();
