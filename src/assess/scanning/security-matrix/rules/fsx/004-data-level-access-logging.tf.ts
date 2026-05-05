import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfFsx004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'FSx-004',
      'HIGH',
      'FSx file system does not have data-level access logging enabled with external storage',
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
        `Configure audit_log_configuration to enable file access logging for the Windows file system.`
      );
    }

    const fileAccessAuditLogLevel = auditLogConfiguration.file_access_audit_log_level;

    if (!fileAccessAuditLogLevel || fileAccessAuditLogLevel === 'DISABLED') {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Enable file access audit logging by setting file_access_audit_log_level to SUCCESS_ONLY, FAILURE_ONLY, or SUCCESS_AND_FAILURE.`
      );
    }

    const auditLogDestination = auditLogConfiguration.audit_log_destination;
    if (!auditLogDestination) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure audit_log_destination to send file access audit logs to CloudWatch Logs.`
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
        `Configure CloudTrail with data event logging for FSx file access events.`
      );
    }

    const hasDataEventTrail = cloudTrails.some(trail => {
      const eventSelectors = trail.values?.event_selector;
      if (!Array.isArray(eventSelectors)) return false;

      return eventSelectors.some((selector: any) => {
        const dataResources = selector.data_resource;
        if (!Array.isArray(dataResources)) return false;

        return dataResources.some((dr: any) =>
          dr.type === 'AWS::FSx::FileSystem'
        );
      });
    });

    if (!hasDataEventTrail) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        `Configure a CloudTrail trail with data event logging for FSx file access events and ensure it logs to S3.`
      );
    }

    return null;
  }
}

export default new TfFsx004Rule();
