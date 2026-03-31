import { describe, it, expect } from 'vitest';
import { FSx003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/fsx/003-system-access-auditing.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('FSx003Rule - System Access Auditing Tests', () => {
  const rule = new FSx003Rule();
  const stackName = 'test-stack';

  // Helper function to create FSx FileSystem test resources
  function createFSxFileSystemResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::FSx::FileSystem',
      Properties: {
        FileSystemType: props.FileSystemType || 'WINDOWS',
        ...props
      },
      LogicalId: props.LogicalId || 'TestFileSystem'
    };
  }

  // Helper function to create CloudTrail Trail test resources
  function createCloudTrailTrailResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::CloudTrail::Trail',
      Properties: {
        IsLogging: props.IsLogging !== undefined ? props.IsLogging : true,
        IsMultiRegionTrail: props.IsMultiRegionTrail !== undefined ? props.IsMultiRegionTrail : true,
        CloudWatchLogsLogGroupArn: props.CloudWatchLogsLogGroupArn || 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group',
        IncludeManagementEvents: props.IncludeManagementEvents !== undefined ? props.IncludeManagementEvents : true,
        EventSelectors: props.EventSelectors || [],
        ...props
      },
      LogicalId: props.LogicalId || 'TestTrail'
    };
  }

  // Helper function to create CloudWatch Logs LogGroup test resources
  function createLogGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::Logs::LogGroup',
      Properties: {
        LogGroupName: props.LogGroupName || 'my-log-group',
        RetentionInDays: props.RetentionInDays || 14,
        ...props
      },
      LogicalId: props.LogicalId || 'TestLogGroup'
    };
  }

  describe('Windows File System Tests', () => {
    it('should detect missing Windows configuration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: undefined
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect missing audit log configuration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {}
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect disabled audit logging', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: 'DISABLED',
            FileShareAccessAuditLogLevel: 'DISABLED'
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect missing audit log destination', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            FileShareAccessAuditLogLevel: 'SUCCESS_AND_FAILURE'
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect invalid audit log destination', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            FileShareAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            AuditLogDestination: 's3://my-bucket'
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should pass with proper audit log configuration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            FileShareAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            AuditLogDestination: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Lustre File System Tests', () => {
    it('should detect missing CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect CloudTrail trail without management events', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IncludeManagementEvents: false
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect CloudTrail trail without logging enabled', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: false
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect CloudTrail trail without CloudWatch Logs', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        CloudWatchLogsLogGroupArn: undefined
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        IncludeManagementEvents: true,
        CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).toBeNull();
    });

    it('should handle CloudTrail trail with intrinsic functions', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: { Ref: 'IsLoggingParam' },
        IncludeManagementEvents: { Ref: 'IncludeManagementEventsParam' },
        CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Note: Found CloudTrail resources with unresolvable properties');
    });
  });

  describe('ONTAP File System Tests', () => {
    it('should detect missing CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {}
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        IncludeManagementEvents: true,
        CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).toBeNull();
    });

    it('should provide guidance when no CloudTrail resources are found', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {}
      });

      // No CloudTrail resources in the template
      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });
  });

  describe('OpenZFS File System Tests', () => {
    it('should detect missing CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'OPENZFS',
        OpenZFSConfiguration: {}
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'OPENZFS',
        OpenZFSConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        IncludeManagementEvents: true,
        CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).toBeNull();
    });

    it('should handle CloudTrail trail with unresolvable properties', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'OPENZFS',
        OpenZFSConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: { 'Fn::GetAtt': ['TrailParam', 'IsLogging'] },
        IncludeManagementEvents: true,
        CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Note: Found CloudTrail resources with unresolvable properties');
    });
  });

  describe('CloudTrail Trail Tests', () => {
    it('should detect non-multi-region trail for FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        IsMultiRegionTrail: false,
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::FSx::FileSystem',
                Values: ['arn:aws:fsx:*:*:*']
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(trail, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect missing CloudWatch Logs for FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        CloudWatchLogsLogGroupArn: undefined,
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::FSx::FileSystem',
                Values: ['arn:aws:fsx:*:*:*']
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(trail, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should detect disabled logging for FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        IsLogging: false,
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::FSx::FileSystem',
                Values: ['arn:aws:fsx:*:*:*']
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(trail, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });

    it('should pass with properly configured trail for FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        IsMultiRegionTrail: true,
        CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group',
        IsLogging: true,
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::FSx::FileSystem',
                Values: ['arn:aws:fsx:*:*:*']
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(trail, stackName);
      expect(result).toBeNull();
    });

    it('should skip trail without FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::S3::Object',
                Values: ['arn:aws:s3:::*/*']
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(trail, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing file system type', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: undefined
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull(); // Skip if file system type is missing
    });

    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::FSx::FileSystem',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Skip if properties are missing
    });

    it('should ignore non-FSx and non-CloudTrail resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    it('should handle intrinsic functions in Windows audit log configuration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: { Ref: 'FileAccessAuditLogLevel' },
            FileShareAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            AuditLogDestination: 'arn:aws:logs:us-east-1:123456789012:log-group:my-log-group'
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull(); // Should pass since FileShareAccessAuditLogLevel is properly configured
    });

    it('should handle intrinsic functions in audit log destination', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            FileShareAccessAuditLogLevel: 'SUCCESS_AND_FAILURE',
            AuditLogDestination: { Ref: 'LogGroupArn' }
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have system access auditing enabled with external logging');
    });
  });
});
