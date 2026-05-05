import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDocdb002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DOCDB-002',
      'HIGH',
      'DocumentDB cluster does not have Log Exports feature enabled',
      ['aws_docdb_cluster']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const enabledCloudwatchLogsExports = resource.values?.enabled_cloudwatch_logs_exports;

    if (!enabledCloudwatchLogsExports) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add enabled_cloudwatch_logs_exports with "audit" to enable audit log exports to CloudWatch Logs.`
      );
    }

    if (!Array.isArray(enabledCloudwatchLogsExports)) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Set enabled_cloudwatch_logs_exports to a list containing "audit".`
      );
    }

    if (enabledCloudwatchLogsExports.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add "audit" to enabled_cloudwatch_logs_exports to enable audit log exports.`
      );
    }

    const hasAudit = enabledCloudwatchLogsExports.some(
      (logType: string) => typeof logType === 'string' && logType.toLowerCase() === 'audit'
    );

    if (!hasAudit) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Add "audit" to enabled_cloudwatch_logs_exports to enable audit log exports.`
      );
    }

    return null;
  }
}

export default new TfDocdb002Rule();
