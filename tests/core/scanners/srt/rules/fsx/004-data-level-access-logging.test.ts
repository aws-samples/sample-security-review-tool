import { describe, it, expect } from 'vitest';
import { FSx004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/fsx/004-data-level-access-logging.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('FSx004Rule - Data-Level Access Logging Tests', () => {
  const rule = new FSx004Rule();
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

  // Helper function to create FSx StorageVirtualMachine test resources
  function createFSxStorageVirtualMachineResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::FSx::StorageVirtualMachine',
      Properties: {
        FileSystemId: props.FileSystemId || 'TestFileSystem',
        ...props
      },
      LogicalId: props.LogicalId || 'TestStorageVirtualMachine'
    };
  }

  // Helper function to create CloudTrail Trail test resources
  function createCloudTrailTrailResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::CloudTrail::Trail',
      Properties: {
        IsLogging: props.IsLogging !== undefined ? props.IsLogging : true,
        S3BucketName: props.S3BucketName || 'my-trail-bucket',
        EventSelectors: props.EventSelectors || [],
        ...props
      },
      LogicalId: props.LogicalId || 'TestTrail'
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should detect missing audit log configuration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {}
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should detect disabled file access audit logging', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          AuditLogConfiguration: {
            FileAccessAuditLogLevel: 'DISABLED',
            FileShareAccessAuditLogLevel: 'SUCCESS_AND_FAILURE'
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should detect CloudTrail trail without FSx data events', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

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

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should detect CloudTrail trail without S3 bucket', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        S3BucketName: undefined,
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

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should detect CloudTrail trail without logging enabled', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

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

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
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

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).toBeNull();
    });

    it('should handle CloudTrail trail with intrinsic functions', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
        EventSelectors: [
          {
            DataResources: [
              {
                Type: { Ref: 'ResourceType' },
                Values: ['arn:aws:fsx:*:*:*']
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Note: Found CloudTrail resources with unresolvable properties');
    });

    it('should provide guidance when no CloudTrail resources are found', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      // No CloudTrail resources in the template
      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
      expect(result?.issue).toContain('Note: No CloudTrail resources found in this template');
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
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

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).toBeNull();
    });

    it('should handle CloudTrail trail with unresolvable values', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::FSx::FileSystem',
                Values: [{ 'Fn::Sub': 'arn:aws:fsx:${AWS::Region}:${AWS::AccountId}:*' }]
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Note: Found CloudTrail resources with unresolvable properties');
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should pass with properly configured CloudTrail trail', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'OPENZFS',
        OpenZFSConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
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

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).toBeNull();
    });

    it('should provide guidance when no CloudTrail resources are found', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'OPENZFS',
        OpenZFSConfiguration: {}
      });

      // No CloudTrail resources in the template
      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Note: No CloudTrail resources found in this template');
    });
  });

  describe('Storage Virtual Machine Tests', () => {
    it('should detect missing Active Directory configuration', () => {
      const svm = createFSxStorageVirtualMachineResource();

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should handle intrinsic functions in Active Directory configuration', () => {
      const svm = createFSxStorageVirtualMachineResource({
        ActiveDirectoryConfiguration: { Ref: 'ActiveDirectoryConfig' }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('ActiveDirectoryConfiguration contains intrinsic functions that cannot be resolved at scan time');
    });
  });

  describe('CloudTrail Trail Tests', () => {
    it('should detect missing S3 bucket for FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        S3BucketName: undefined,
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
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
      expect(result?.issue).toContain('FSx file system does not have data-level access logging enabled with external storage');
    });

    it('should pass with properly configured trail for FSx data events', () => {
      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
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

    it('should ignore non-FSx, non-SVM, and non-CloudTrail resources', () => {
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

    it('should fail with intrinsic functions in Windows audit log configuration', () => {
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

      // The rule implementation fails when FileAccessAuditLogLevel is unresolvable
      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Enable file access audit logging');
    });

    it('should handle complex intrinsic functions in CloudTrail event selectors', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'LUSTRE',
        LustreConfiguration: {}
      });

      const trail = createCloudTrailTrailResource({
        IsLogging: true,
        S3BucketName: 'my-trail-bucket',
        EventSelectors: [
          {
            DataResources: [
              {
                Type: 'AWS::FSx::FileSystem',
                Values: [
                  {
                    'Fn::Join': [
                      '',
                      ['arn:aws:fsx:', { Ref: 'AWS::Region' }, ':', { Ref: 'AWS::AccountId' }, ':*']
                    ]
                  }
                ]
              }
            ]
          }
        ]
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, trail]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Note: Found CloudTrail resources with unresolvable properties');
    });
  });
});
