import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class DocumentDB002Rule extends BaseRule {
  constructor() {
    super(
      'DOCDB-002',
      'HIGH',
      'DocumentDB cluster does not have Log Exports feature enabled',
      ['AWS::DocDB::DBCluster']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    // Check if this rule applies to the resource type
    if (!this.appliesTo(resource.Type)) {
      return null;
    }

    // Handle missing Properties
    if (!resource.Properties) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure EnableCloudwatchLogsExports with 'audit' to publish audit logs to CloudWatch Logs.`
      );
    }

    if (resource.Type === 'AWS::DocDB::DBCluster') {
      return this.evaluateCluster(resource, stackName);
    }

    return null;
  }

  private evaluateCluster(resource: CloudFormationResource, stackName: string): ScanResult | null {
    const logExports = resource.Properties.EnableCloudwatchLogsExports;

    // If EnableCloudwatchLogsExports is not specified, log exports are disabled
    if (!logExports) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add EnableCloudwatchLogsExports property with 'audit' to enable audit log exports to CloudWatch Logs.`
      );
    }

    // Handle CloudFormation intrinsic functions
    if (typeof logExports === 'object' && !Array.isArray(logExports)) {
      // Could be a Ref, GetAtt, or other intrinsic function
      // We can't determine the actual value at scan time, so flag as non-compliant
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EnableCloudwatchLogsExports to an explicit array containing 'audit' rather than using CloudFormation functions that cannot be validated at scan time.`
      );
    }

    // EnableCloudwatchLogsExports should be an array
    if (!Array.isArray(logExports)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Set EnableCloudwatchLogsExports to an array containing 'audit' (current value: ${logExports}).`
      );
    }

    // Check if the array is empty
    if (logExports.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add 'audit' to the EnableCloudwatchLogsExports array to enable audit log exports.`
      );
    }

    // Check if 'audit' is included in the log exports array
    const auditCheckResult = this.checkForAuditLogging(logExports);

    if (auditCheckResult === 'intrinsic_function') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Use explicit string values in EnableCloudwatchLogsExports array rather than CloudFormation functions that cannot be validated at scan time.`
      );
    }

    if (!auditCheckResult) {
      const currentExports = logExports.join(', ');
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Add 'audit' to EnableCloudwatchLogsExports array to enable audit log exports (current exports: ${currentExports}).`
      );
    }

    // Compliant: audit logging is enabled
    return null;
  }

  private checkForAuditLogging(logExports: any[]): boolean | string {
    for (const logType of logExports) {
      // Handle string values
      if (typeof logType === 'string' && logType.toLowerCase() === 'audit') {
        return true;
      }

      // Handle CloudFormation intrinsic functions within the array
      // If we encounter any intrinsic functions, we can't verify compliance at scan time
      if (typeof logType === 'object') {
        return 'intrinsic_function';
      }
    }

    return false;
  }
}

export default new DocumentDB002Rule();