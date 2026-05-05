import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfFsx003Rule extends BaseTerraformRule {
  constructor() {
    super(
      'FSx-003',
      'HIGH',
      'FSx file system does not have system access auditing enabled with external logging',
      ['aws_fsx_windows_file_system', 'aws_fsx_lustre_file_system', 'aws_fsx_ontap_file_system', 'aws_fsx_openzfs_file_system']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_fsx_windows_file_system') {
      return this.evaluateWindowsFileSystem(resource, projectName);
    }

    return this.evaluateNonWindowsFileSystem(resource, projectName, allResources);
  }

  private evaluateWindowsFileSystem(resource: TerraformResource, projectName: string): ScanResult | null {
    const auditLogConfiguration = resource.values?.audit_log_configuration;

    if (!auditLogConfiguration) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure audit_log_configuration to enable audit logging for the Windows file system.`
      );
    }

    const fileAccessAuditLogLevel = auditLogConfiguration.file_access_audit_log_level;
    const fileShareAccessAuditLogLevel = auditLogConfiguration.file_share_access_audit_log_level;

    if (fileAccessAuditLogLevel === 'DISABLED' && fileShareAccessAuditLogLevel === 'DISABLED') {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Enable audit logging by setting file_access_audit_log_level and/or file_share_access_audit_log_level to SUCCESS_ONLY, FAILURE_ONLY, or SUCCESS_AND_FAILURE.`
      );
    }

    const auditLogDestination = auditLogConfiguration.audit_log_destination;
    if (!auditLogDestination) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure audit_log_destination to send audit logs to CloudWatch Logs.`
      );
    }

    return null;
  }

  private evaluateNonWindowsFileSystem(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    const cloudTrails = allResources.filter(r => r.type === 'aws_cloudtrail');

    if (cloudTrails.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure CloudTrail to capture FSx API events and ensure logs are sent to CloudWatch Logs.`
      );
    }

    const hasValidTrail = cloudTrails.some(trail => {
      const enableLogging = trail.values?.enable_logging;
      const cloudWatchLogsGroupArn = trail.values?.cloud_watch_logs_group_arn;
      return enableLogging !== false && !!cloudWatchLogsGroupArn;
    });

    if (!hasValidTrail) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure a CloudTrail trail with enable_logging = true and cloud_watch_logs_group_arn to capture FSx API events.`
      );
    }

    return null;
  }
}

export default new TfFsx003Rule();
