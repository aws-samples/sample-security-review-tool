import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * FSx3 Rule: Ensure system access auditing is enabled and that the logs are collected somewhere other than the local system.
 * 
 * Documentation: "Administrative events and other system access events to file servers and storage virtual machines (SVMs)
 * should be logged to an external location to support incident response practices."
 */
export class FSx003Rule extends BaseRule {
  constructor() {
    super(
      'FSx-003',
      'HIGH',
      'FSx file system does not have system access auditing enabled with external logging',
      [
        'AWS::FSx::FileSystem',
        'AWS::Logs::LogGroup',
        'AWS::CloudTrail::Trail'
      ]
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    const resolver = new CloudFormationResolver(allResources);

    // For FSx FileSystem resources
    if (resource.Type === 'AWS::FSx::FileSystem') {
      const fileSystemType = resource.Properties?.FileSystemType;

      // Check if the file system type is specified
      if (!fileSystemType) {
        return null;
      }

      // Check for Windows File Server
      if (fileSystemType === 'WINDOWS') {
        return this.evaluateWindowsFileSystem(resource, stackName, resolver);
      }

      // Check for Lustre
      if (fileSystemType === 'LUSTRE') {
        return this.evaluateLustreFileSystem(resource, stackName, allResources, resolver);
      }

      // Check for ONTAP
      if (fileSystemType === 'ONTAP') {
        return this.evaluateOntapFileSystem(resource, stackName, allResources, resolver);
      }

      // Check for OpenZFS
      if (fileSystemType === 'OPENZFS') {
        return this.evaluateOpenZfsFileSystem(resource, stackName, allResources, resolver);
      }
    }

    // For CloudTrail Trail resources
    if (resource.Type === 'AWS::CloudTrail::Trail') {
      // Check if the trail includes FSx data events
      const eventSelectors = resource.Properties?.EventSelectors;

      if (!eventSelectors || !Array.isArray(eventSelectors) || eventSelectors.length === 0) {
        return null;
      }

      // Check if any event selector includes FSx data events
      const hasFsxDataEvents = eventSelectors.some(selector => {
        const dataResources = selector.DataResources;

        if (!dataResources || !Array.isArray(dataResources)) {
          return false;
        }

        return dataResources.some(dataResource => {
          const type = dataResource.Type;
          const values = dataResource.Values;

          if (!type || !values || !Array.isArray(values)) {
            return false;
          }

          // Check if the type is AWS::FSx::FileSystem
          if (type !== 'AWS::FSx::FileSystem') {
            return false;
          }

          // Check if values include FSx ARNs or wildcards
          return values.some(value => {
            if (typeof value === 'string') {
              return value.includes('fsx') || value.includes('*');
            }
            return false;
          });
        });
      });

      // If this trail includes FSx data events, check if it's properly configured
      if (hasFsxDataEvents) {
        // Check if the trail is multi-region
        const isMultiRegion = resource.Properties?.IsMultiRegionTrail;
        const resolvedIsMultiRegion = resolver.resolve(isMultiRegion);

        if (!resolvedIsMultiRegion.isResolved || resolvedIsMultiRegion.value !== true) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Configure the CloudTrail trail as multi-region to capture FSx events from all regions.`
          );
        }

        // Check if the trail logs to CloudWatch Logs
        const cloudWatchLogsLogGroupArn = resource.Properties?.CloudWatchLogsLogGroupArn;

        if (!cloudWatchLogsLogGroupArn) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Configure the CloudTrail trail to send logs to CloudWatch Logs for centralized monitoring.`
          );
        }

        // Check if the trail is enabled
        const isTrailEnabled = resource.Properties?.IsLogging;
        const resolvedIsTrailEnabled = resolver.resolve(isTrailEnabled);

        if (!resolvedIsTrailEnabled.isResolved || resolvedIsTrailEnabled.value !== true) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Enable logging for the CloudTrail trail by setting IsLogging to true.`
          );
        }
      }
    }

    return null;
  }

  private evaluateWindowsFileSystem(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    const windowsConfiguration = resource.Properties?.WindowsConfiguration;

    if (!windowsConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure WindowsConfiguration with audit log settings.`
      );
    }

    // Check for audit log configuration
    const auditLogConfiguration = windowsConfiguration.AuditLogConfiguration;

    if (!auditLogConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure AuditLogConfiguration to enable audit logging for the Windows file system.`
      );
    }

    // Check if audit logging is enabled
    const fileAccessAuditLogLevel = auditLogConfiguration.FileAccessAuditLogLevel;
    const fileShareAccessAuditLogLevel = auditLogConfiguration.FileShareAccessAuditLogLevel;

    const resolvedFileAccessLevel = resolver.resolve(fileAccessAuditLogLevel);
    const resolvedFileShareLevel = resolver.resolve(fileShareAccessAuditLogLevel);

    // If we can't resolve the values or they are disabled, fail the check
    if ((!resolvedFileAccessLevel.isResolved || resolvedFileAccessLevel.value === 'DISABLED') &&
      (!resolvedFileShareLevel.isResolved || resolvedFileShareLevel.value === 'DISABLED')) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable audit logging by setting FileAccessAuditLogLevel and/or FileShareAccessAuditLogLevel to 'SUCCESS_ONLY' or 'FAILURE_ONLY' or 'SUCCESS_AND_FAILURE'.`
      );
    }

    // Check if logs are sent to CloudWatch Logs
    const auditLogDestination = auditLogConfiguration.AuditLogDestination;

    if (!auditLogDestination) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure AuditLogDestination to send audit logs to CloudWatch Logs.`
      );
    }

    // Check if the destination is a CloudWatch Logs log group
    const resolvedDestination = resolver.resolve(auditLogDestination);

    if (!resolvedDestination.isResolved ||
      (typeof resolvedDestination.value === 'string' && !resolvedDestination.value.includes('logs:'))) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure AuditLogDestination to send audit logs to a CloudWatch Logs log group.`
      );
    }

    return null;
  }

  private evaluateLustreFileSystem(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[] | undefined, resolver: CloudFormationResolver): ScanResult | null {
    // Lustre file systems don't have built-in audit logging, so we need to check for CloudTrail
    if (!allResources || !Array.isArray(allResources)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail to capture FSx Lustre API events and data events.`
      );
    }

    // Check if there's a CloudTrail trail that captures FSx events
    const cloudTrailTrails = allResources.filter(res => res.Type === 'AWS::CloudTrail::Trail');

    // If no CloudTrail resources are found in this template, provide guidance but don't fail
    // This handles the case where CloudTrail might be defined in another stack
    if (cloudTrailTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: No CloudTrail resources found in this template. If CloudTrail is defined in another stack, ensure it captures FSx Lustre API events, has logging enabled, and sends logs to CloudWatch Logs.`
      );
    }

    // Check if any trail captures FSx events
    let hasUnresolvableTrail = false;
    const hasFsxTrail = cloudTrailTrails.some(trail => {
      // Check if the trail includes management events (which would include FSx API calls)
      const includeManagementEvents = trail.Properties?.IncludeManagementEvents;

      const resolvedIncludeManagementEvents = resolver.resolve(includeManagementEvents);
      if (!resolvedIncludeManagementEvents.isResolved) {
        hasUnresolvableTrail = true;
        return false;
      }

      if (resolvedIncludeManagementEvents.value !== true) {
        return false;
      }

      // Check if the trail is enabled
      const isTrailEnabled = trail.Properties?.IsLogging;

      const resolvedIsTrailEnabled = resolver.resolve(isTrailEnabled);
      if (!resolvedIsTrailEnabled.isResolved) {
        hasUnresolvableTrail = true;
        return false;
      }

      if (resolvedIsTrailEnabled.value !== true) {
        return false;
      }

      // Check if the trail logs to CloudWatch Logs
      const cloudWatchLogsLogGroupArn = trail.Properties?.CloudWatchLogsLogGroupArn;

      if (!cloudWatchLogsLogGroupArn) {
        return false;
      }

      // If we've made it this far, this trail is properly configured
      return true;
    });

    // If we found a trail with unresolvable properties, provide guidance but don't fail
    if (hasUnresolvableTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: Found CloudTrail resources with unresolvable properties (possibly using intrinsic functions). Ensure CloudTrail captures FSx Lustre API events, has logging enabled, and sends logs to CloudWatch Logs.`
      );
    }

    // If no properly configured trail was found, fail the check
    if (!hasFsxTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure a CloudTrail trail to capture FSx Lustre API events, enable logging, and send logs to CloudWatch Logs.`
      );
    }

    return null;
  }

  private evaluateOntapFileSystem(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[] | undefined, resolver: CloudFormationResolver): ScanResult | null {
    // ONTAP file systems support audit logging through SVMs
    // Check if there are any associated SVMs with audit logging enabled
    if (!allResources || !Array.isArray(allResources)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail to capture FSx ONTAP API events and data events.`
      );
    }

    // Check if there's a CloudTrail trail that captures FSx events
    const cloudTrailTrails = allResources.filter(res => res.Type === 'AWS::CloudTrail::Trail');

    // If no CloudTrail resources are found in this template, provide guidance but don't fail
    // This handles the case where CloudTrail might be defined in another stack
    if (cloudTrailTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: No CloudTrail resources found in this template. If CloudTrail is defined in another stack, ensure it captures FSx ONTAP API events, has logging enabled, and sends logs to CloudWatch Logs.`
      );
    }

    // Check if any trail captures FSx events
    let hasUnresolvableTrail = false;
    const hasFsxTrail = cloudTrailTrails.some(trail => {
      // Check if the trail includes management events (which would include FSx API calls)
      const includeManagementEvents = trail.Properties?.IncludeManagementEvents;

      const resolvedIncludeManagementEvents = resolver.resolve(includeManagementEvents);
      if (!resolvedIncludeManagementEvents.isResolved) {
        hasUnresolvableTrail = true;
        return false;
      }

      if (resolvedIncludeManagementEvents.value !== true) {
        return false;
      }

      // Check if the trail is enabled
      const isTrailEnabled = trail.Properties?.IsLogging;

      const resolvedIsTrailEnabled = resolver.resolve(isTrailEnabled);
      if (!resolvedIsTrailEnabled.isResolved) {
        hasUnresolvableTrail = true;
        return false;
      }

      if (resolvedIsTrailEnabled.value !== true) {
        return false;
      }

      // Check if the trail logs to CloudWatch Logs
      const cloudWatchLogsLogGroupArn = trail.Properties?.CloudWatchLogsLogGroupArn;

      if (!cloudWatchLogsLogGroupArn) {
        return false;
      }

      // If we've made it this far, this trail is properly configured
      return true;
    });

    // If we found a trail with unresolvable properties, provide guidance but don't fail
    if (hasUnresolvableTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: Found CloudTrail resources with unresolvable properties (possibly using intrinsic functions). Ensure CloudTrail captures FSx ONTAP API events, has logging enabled, and sends logs to CloudWatch Logs.`
      );
    }

    // If no properly configured trail was found, fail the check
    if (!hasFsxTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure a CloudTrail trail to capture FSx ONTAP API events, enable logging, and send logs to CloudWatch Logs.`
      );
    }

    return null;
  }

  private evaluateOpenZfsFileSystem(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[] | undefined, resolver: CloudFormationResolver): ScanResult | null {
    // OpenZFS file systems don't have built-in audit logging, so we need to check for CloudTrail
    if (!allResources || !Array.isArray(allResources)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail to capture FSx OpenZFS API events and data events.`
      );
    }

    // Check if there's a CloudTrail trail that captures FSx events
    const cloudTrailTrails = allResources.filter(res => res.Type === 'AWS::CloudTrail::Trail');

    // If no CloudTrail resources are found in this template, provide guidance but don't fail
    // This handles the case where CloudTrail might be defined in another stack
    if (cloudTrailTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: No CloudTrail resources found in this template. If CloudTrail is defined in another stack, ensure it captures FSx OpenZFS API events, has logging enabled, and sends logs to CloudWatch Logs.`
      );
    }

    // Check if any trail captures FSx events
    let hasUnresolvableTrail = false;
    const hasFsxTrail = cloudTrailTrails.some(trail => {
      // Check if the trail includes management events (which would include FSx API calls)
      const includeManagementEvents = trail.Properties?.IncludeManagementEvents;

      const resolvedIncludeManagementEvents = resolver.resolve(includeManagementEvents);
      if (!resolvedIncludeManagementEvents.isResolved) {
        hasUnresolvableTrail = true;
        return false;
      }

      if (resolvedIncludeManagementEvents.value !== true) {
        return false;
      }

      // Check if the trail is enabled
      const isTrailEnabled = trail.Properties?.IsLogging;

      const resolvedIsTrailEnabled = resolver.resolve(isTrailEnabled);
      if (!resolvedIsTrailEnabled.isResolved) {
        hasUnresolvableTrail = true;
        return false;
      }

      if (resolvedIsTrailEnabled.value !== true) {
        return false;
      }

      // Check if the trail logs to CloudWatch Logs
      const cloudWatchLogsLogGroupArn = trail.Properties?.CloudWatchLogsLogGroupArn;

      if (!cloudWatchLogsLogGroupArn) {
        return false;
      }

      // If we've made it this far, this trail is properly configured
      return true;
    });

    // If we found a trail with unresolvable properties, provide guidance but don't fail
    if (hasUnresolvableTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: Found CloudTrail resources with unresolvable properties (possibly using intrinsic functions). Ensure CloudTrail captures FSx OpenZFS API events, has logging enabled, and sends logs to CloudWatch Logs.`
      );
    }

    // If no properly configured trail was found, fail the check
    if (!hasFsxTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure a CloudTrail trail to capture FSx OpenZFS API events, enable logging, and send logs to CloudWatch Logs.`
      );
    }

    return null;
  }
}

export default new FSx003Rule();
