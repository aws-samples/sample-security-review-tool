import { describe, it, expect } from 'vitest';
import { FSxN003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/fsx/n003-ssh-private-key-access.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('FSxN003Rule - SSH Private Key Access Tests', () => {
  const rule = new FSxN003Rule();
  const stackName = 'test-stack';

  // Helper function to create FSx FileSystem test resources
  function createFSxFileSystemResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::FSx::FileSystem',
      Properties: {
        FileSystemType: props.FileSystemType || 'ONTAP',
        OntapConfiguration: props.OntapConfiguration || {},
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

  describe('FSx ONTAP FileSystem Tests', () => {
    it('should detect password authentication', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {
          FsxAdminPassword: 'Password123'
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH access to file system and/or SVMs is not configured to use private key authentication');
    });

    it('should detect unresolvable password authentication', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {
          FsxAdminPassword: { 'Ref': 'AdminPassword' }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should detect CDK token pattern in password', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {
          FsxAdminPassword: {
            'Fn::Join': [
              '',
              [
                '${Token[',
                { 'Ref': 'AdminPassword' },
                '.12345]}'
              ]
            ]
          }
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should pass without password authentication', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: {
          // No FsxAdminPassword specified, implying SSH key authentication
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull();
    });

    it('should pass with non-ONTAP file system', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          // Windows file systems use different authentication mechanisms
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull();
    });

    it('should handle unresolvable file system type', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: { 'Ref': 'FileSystemType' },
        OntapConfiguration: {
          FsxAdminPassword: 'Password123'
        }
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull(); // Should skip if file system type can't be resolved
    });
  });

  describe('Storage Virtual Machine Tests', () => {
    it('should detect password authentication', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: 'Password123'
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH access to file system and/or SVMs is not configured to use private key authentication');
    });

    it('should detect unresolvable SVM password authentication', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: { 'Ref': 'SvmAdminPassword' }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should detect Active Directory password authentication', () => {
      const svm = createFSxStorageVirtualMachineResource({
        ActiveDirectoryConfiguration: {
          NetBiosName: 'TESTVM',
          SelfManagedActiveDirectoryConfiguration: {
            DomainName: 'example.com',
            OrganizationalUnitDistinguishedName: 'OU=FSx,DC=example,DC=com',
            FileSystemAdministratorsGroup: 'FSx Admins',
            UserName: 'Admin',
            Password: 'Password123'
          }
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH access to file system and/or SVMs is not configured to use private key authentication');
    });

    it('should detect unresolvable Active Directory password authentication', () => {
      const svm = createFSxStorageVirtualMachineResource({
        ActiveDirectoryConfiguration: {
          NetBiosName: 'TESTVM',
          SelfManagedActiveDirectoryConfiguration: {
            DomainName: 'example.com',
            OrganizationalUnitDistinguishedName: 'OU=FSx,DC=example,DC=com',
            FileSystemAdministratorsGroup: 'FSx Admins',
            UserName: 'Admin',
            Password: { 'Ref': 'ADPassword' }
          }
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should detect missing authentication configuration', () => {
      const svm = createFSxStorageVirtualMachineResource();

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH access to file system and/or SVMs is not configured to use private key authentication');
    });

    it('should detect Active Directory configuration without password', () => {
      const svm = createFSxStorageVirtualMachineResource({
        ActiveDirectoryConfiguration: {
          NetBiosName: 'TESTVM',
          SelfManagedActiveDirectoryConfiguration: {
            DomainName: 'example.com',
            OrganizationalUnitDistinguishedName: 'OU=FSx,DC=example,DC=com',
            FileSystemAdministratorsGroup: 'FSx Admins',
            UserName: 'Admin'
            // No Password specified, but the rule still requires explicit SSH key configuration
          }
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should detect unresolvable direct AD password', () => {
      const svm = createFSxStorageVirtualMachineResource({
        ActiveDirectoryConfiguration: {
          NetBiosName: 'TESTVM',
          Password: { 'Ref': 'DirectADPassword' }
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should detect SSM parameter reference in password', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: {
          'Fn::Sub': '{{resolve:ssm:/fsx/admin-password:1}}'
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });

    it('should detect Secrets Manager reference in password', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: {
          'Fn::Join': ['', ['{{resolve:secretsmanager:', { 'Ref': 'AdminSecret' }, ':SecretString:password}}']]
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::FSx::FileSystem',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull(); // Skip if properties are missing
    });

    it('should handle missing OntapConfiguration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: undefined
      });

      const result = rule.evaluate(fileSystem, stackName);
      expect(result).toBeNull(); // Skip if OntapConfiguration is missing
    });

    it('should ignore non-FSx resources', () => {
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

    it('should handle complex intrinsic functions in file system ID', () => {
      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: {
          'Fn::GetAtt': ['TestFileSystem', 'FileSystemId']
        },
        SvmAdminPassword: 'Password123'
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH access to file system and/or SVMs is not configured to use private key authentication');
    });

    it('should handle nested intrinsic functions', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: {
          'Fn::If': [
            'UseSecurePassword',
            { 'Ref': 'SecurePassword' },
            'DefaultPassword'
          ]
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify authentication method at scan time due to intrinsic functions');
    });
  });
});
