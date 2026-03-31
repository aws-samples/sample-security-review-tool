import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { CloudFormationResolver } from '../../resolver.js';

/**
 * FSx4 Rule: Ensure file/object/data-level access logging is enabled and events for user access and file modification are collected in an external location.
 * 
 * Documentation: "If the FSx implementation supports it, ensure appropriate access and modification logging is enabled and
 * saved to an external (off-system) location like S3."
 */
export class FSx004Rule extends BaseRule {
  constructor() {
    super(
      'FSx-004',
      'HIGH',
      'FSx file system does not have data-level access logging enabled with external storage',
      [
        'AWS::FSx::FileSystem',
        'AWS::FSx::StorageVirtualMachine',
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

    // For FSx StorageVirtualMachine resources (ONTAP)
    if (resource.Type === 'AWS::FSx::StorageVirtualMachine') {
      return this.evaluateStorageVirtualMachine(resource, stackName, resolver);
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

      // If this trail includes FSx data events, check if it's properly configured for data-level logging
      if (hasFsxDataEvents) {
        // Check if the trail logs to S3
        const s3BucketName = resource.Properties?.S3BucketName;

        if (!s3BucketName) {
          return this.createScanResult(
            resource,
            stackName,
            `${this.description}`,
            `Configure the CloudTrail trail to send logs to an S3 bucket for long-term storage.`
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
        `Configure AuditLogConfiguration to enable file access logging for the Windows file system.`
      );
    }

    // Check if file access audit logging is enabled
    const fileAccessAuditLogLevel = auditLogConfiguration.FileAccessAuditLogLevel;
    const resolvedFileAccessLevel = resolver.resolve(fileAccessAuditLogLevel);

    if (!resolvedFileAccessLevel.isResolved || resolvedFileAccessLevel.value === 'DISABLED') {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Enable file access audit logging by setting FileAccessAuditLogLevel to 'SUCCESS_ONLY' or 'FAILURE_ONLY' or 'SUCCESS_AND_FAILURE'.`
      );
    }

    // Check if logs are sent to CloudWatch Logs
    const auditLogDestination = auditLogConfiguration.AuditLogDestination;

    if (!auditLogDestination) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure AuditLogDestination to send file access audit logs to CloudWatch Logs.`
      );
    }

    return null;
  }

  private evaluateLustreFileSystem(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[] | undefined, resolver: CloudFormationResolver): ScanResult | null {
    // Lustre file systems don't have built-in file-level access logging
    // We need to check for CloudTrail data events
    if (!allResources || !Array.isArray(allResources)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail with data event logging for FSx Lustre file access events.`
      );
    }

    // Check if there's a CloudTrail trail that captures FSx data events
    const cloudTrailTrails = allResources.filter(res => res.Type === 'AWS::CloudTrail::Trail');

    // If no CloudTrail resources are found in this template, provide guidance but don't fail
    // This handles the case where CloudTrail might be defined in another stack
    if (cloudTrailTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: No CloudTrail resources found in this template. If CloudTrail is defined in another stack, ensure it captures FSx Lustre data events, has logging enabled, and sends logs to S3.`
      );
    }

    // Check if any trail captures FSx data events and is properly configured
    let validTrailFound = false;
    let hasUnresolvableTrail = false;

    for (const trail of cloudTrailTrails) {
      const eventSelectors = trail.Properties?.EventSelectors;

      if (!eventSelectors || !Array.isArray(eventSelectors) || eventSelectors.length === 0) {
        continue;
      }

      // Check if any event selector includes FSx data events
      let hasFsxDataEvents = false;

      for (const selector of eventSelectors) {
        const dataResources = selector.DataResources;

        if (!dataResources || !Array.isArray(dataResources)) {
          continue;
        }

        for (const dataResource of dataResources) {
          const type = dataResource.Type;
          const values = dataResource.Values;

          if (!type || !values || !Array.isArray(values)) {
            continue;
          }

          // Check if the type is AWS::FSx::FileSystem
          const resolvedType = resolver.resolve(type);
          if (!resolvedType.isResolved) {
            hasUnresolvableTrail = true;
            continue;
          }

          if (resolvedType.value !== 'AWS::FSx::FileSystem') {
            continue;
          }

          // Check if values include FSx ARNs or wildcards
          let hasValidValue = false;
          for (const value of values) {
            const resolvedValue = resolver.resolve(value);
            if (!resolvedValue.isResolved) {
              hasUnresolvableTrail = true;
              continue;
            }

            if (typeof resolvedValue.value === 'string' &&
              (resolvedValue.value.includes('fsx') || resolvedValue.value.includes('*'))) {
              hasValidValue = true;
              break;
            }
          }

          if (hasValidValue) {
            hasFsxDataEvents = true;
            break;
          }
        }

        if (hasFsxDataEvents) {
          break;
        }
      }

      if (hasFsxDataEvents) {
        // Check if the trail logs to S3
        const s3BucketName = trail.Properties?.S3BucketName;

        if (!s3BucketName) {
          continue; // This trail doesn't log to S3, so it's not valid
        }

        // Check if the trail is enabled
        const isTrailEnabled = trail.Properties?.IsLogging;
        const resolvedIsTrailEnabled = resolver.resolve(isTrailEnabled);

        if (!resolvedIsTrailEnabled.isResolved) {
          hasUnresolvableTrail = true;
          continue;
        }

        if (resolvedIsTrailEnabled.value !== true) {
          continue; // This trail is not enabled, so it's not valid
        }

        // If we get here, we found a valid trail
        validTrailFound = true;
        break;
      }
    }

    // If we found a trail with unresolvable properties, provide guidance but don't fail
    if (hasUnresolvableTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: Found CloudTrail resources with unresolvable properties (possibly using intrinsic functions). Ensure CloudTrail captures FSx Lustre data events, has logging enabled, and sends logs to S3.`
      );
    }

    // If no properly configured trail was found, fail the check
    if (!validTrailFound) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure a CloudTrail trail with data event logging for FSx file access events, ensure it logs to S3 and is enabled.`
      );
    }

    return null;
  }

  private evaluateOntapFileSystem(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[] | undefined, resolver: CloudFormationResolver): ScanResult | null {
    // ONTAP file systems support file access auditing through SVMs
    // Check if there are any associated SVMs with file access auditing enabled
    if (!allResources || !Array.isArray(allResources)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail with data event logging for FSx ONTAP file access events.`
      );
    }

    // Check if there's a CloudTrail trail that captures FSx data events
    const cloudTrailTrails = allResources.filter(res => res.Type === 'AWS::CloudTrail::Trail');

    // If no CloudTrail resources are found in this template, provide guidance but don't fail
    // This handles the case where CloudTrail might be defined in another stack
    if (cloudTrailTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: No CloudTrail resources found in this template. If CloudTrail is defined in another stack, ensure it captures FSx ONTAP data events, has logging enabled, and sends logs to S3.`
      );
    }

    // Check if any trail captures FSx data events
    let hasUnresolvableTrail = false;
    const hasFsxDataEvents = cloudTrailTrails.some(trail => {
      const eventSelectors = trail.Properties?.EventSelectors;

      if (!eventSelectors || !Array.isArray(eventSelectors) || eventSelectors.length === 0) {
        return false;
      }

      // Check if any event selector includes FSx data events
      return eventSelectors.some(selector => {
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
          const resolvedType = resolver.resolve(type);
          if (!resolvedType.isResolved) {
            hasUnresolvableTrail = true;
            return false;
          }

          if (resolvedType.value !== 'AWS::FSx::FileSystem') {
            return false;
          }

          // Check if values include FSx ARNs or wildcards
          const hasValidValue = values.some(value => {
            const resolvedValue = resolver.resolve(value);
            if (!resolvedValue.isResolved) {
              hasUnresolvableTrail = true;
              return false;
            }

            if (typeof resolvedValue.value === 'string') {
              return resolvedValue.value.includes('fsx') || resolvedValue.value.includes('*');
            }
            return false;
          });

          return hasValidValue;
        });
      });
    });

    // If we found a trail with unresolvable properties, provide guidance but don't fail
    if (hasUnresolvableTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: Found CloudTrail resources with unresolvable properties (possibly using intrinsic functions). Ensure CloudTrail captures FSx ONTAP data events, has logging enabled, and sends logs to S3.`
      );
    }

    // If no properly configured trail was found, fail the check
    if (!hasFsxDataEvents) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure a CloudTrail trail with data event logging for FSx ONTAP file access events.`
      );
    }

    return null;
  }

  private evaluateOpenZfsFileSystem(resource: CloudFormationResource, stackName: string, allResources: CloudFormationResource[] | undefined, resolver: CloudFormationResolver): ScanResult | null {
    // OpenZFS file systems don't have built-in file-level access logging
    // We need to check for CloudTrail data events
    if (!allResources || !Array.isArray(allResources)) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure CloudTrail with data event logging for FSx OpenZFS file access events.`
      );
    }

    // Check if there's a CloudTrail trail that captures FSx data events
    const cloudTrailTrails = allResources.filter(res => res.Type === 'AWS::CloudTrail::Trail');

    // If no CloudTrail resources are found in this template, provide guidance but don't fail
    // This handles the case where CloudTrail might be defined in another stack
    if (cloudTrailTrails.length === 0) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: No CloudTrail resources found in this template. If CloudTrail is defined in another stack, ensure it captures FSx OpenZFS data events, has logging enabled, and sends logs to S3.`
      );
    }

    // Check if any trail captures FSx data events
    let hasUnresolvableTrail = false;
    const hasFsxDataEvents = cloudTrailTrails.some(trail => {
      const eventSelectors = trail.Properties?.EventSelectors;

      if (!eventSelectors || !Array.isArray(eventSelectors) || eventSelectors.length === 0) {
        return false;
      }

      // Check if any event selector includes FSx data events
      return eventSelectors.some(selector => {
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
          const resolvedType = resolver.resolve(type);
          if (!resolvedType.isResolved) {
            hasUnresolvableTrail = true;
            return false;
          }

          if (resolvedType.value !== 'AWS::FSx::FileSystem') {
            return false;
          }

          // Check if values include FSx ARNs or wildcards
          const hasValidValue = values.some(value => {
            const resolvedValue = resolver.resolve(value);
            if (!resolvedValue.isResolved) {
              hasUnresolvableTrail = true;
              return false;
            }

            if (typeof resolvedValue.value === 'string') {
              return resolvedValue.value.includes('fsx') || resolvedValue.value.includes('*');
            }
            return false;
          });

          return hasValidValue;
        });
      });
    });

    // If we found a trail with unresolvable properties, provide guidance but don't fail
    if (hasUnresolvableTrail) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}. Note: Found CloudTrail resources with unresolvable properties (possibly using intrinsic functions). Ensure CloudTrail captures FSx OpenZFS data events, has logging enabled, and sends logs to S3.`
      );
    }

    // If no properly configured trail was found, fail the check
    if (!hasFsxDataEvents) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure a CloudTrail trail with data event logging for FSx OpenZFS file access events.`
      );
    }

    return null;
  }

  private evaluateStorageVirtualMachine(resource: CloudFormationResource, stackName: string, resolver: CloudFormationResolver): ScanResult | null {
    // ONTAP SVMs can have audit logging configured, but this is typically done through the ONTAP CLI
    // For CloudFormation, we can only check if the SVM is properly configured for security

    // Check for Active Directory configuration for proper authentication
    const activeDirectoryConfiguration = resource.Properties?.ActiveDirectoryConfiguration;

    if (!activeDirectoryConfiguration) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `Configure ActiveDirectoryConfiguration for proper authentication and auditing capabilities.`
      );
    }

    // Use resolver to check if ActiveDirectoryConfiguration is properly configured
    const resolvedActiveDirectoryConfig = resolver.resolve(activeDirectoryConfiguration);
    if (!resolvedActiveDirectoryConfig.isResolved) {
      return this.createScanResult(
        resource,
        stackName,
        `${this.description}`,
        `ActiveDirectoryConfiguration contains intrinsic functions that cannot be resolved at scan time. Ensure it is properly configured for authentication and auditing.`
      );
    }

    return null;
  }
}

export default new FSx004Rule();
