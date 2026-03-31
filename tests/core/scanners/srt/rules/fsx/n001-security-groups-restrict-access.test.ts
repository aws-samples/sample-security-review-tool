import { describe, it, expect } from 'vitest';
import { FSxN001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/fsx/n001-security-groups-restrict-access.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('FSxN001Rule - Security Groups Restrict Access Tests', () => {
  const rule = new FSxN001Rule();
  const stackName = 'test-stack';

  // Helper function to create FSx FileSystem test resources
  function createFSxFileSystemResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::FSx::FileSystem',
      Properties: {
        FileSystemType: props.FileSystemType || 'ONTAP',
        OntapConfiguration: props.OntapConfiguration || {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: props.SecurityGroupIds || ['sg-12345']
        },
        ...props
      },
      LogicalId: props.LogicalId || 'TestFileSystem'
    };
  }

  // Helper function to create Security Group test resources
  function createSecurityGroupResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroup',
      Properties: {
        GroupDescription: 'Test Security Group',
        VpcId: 'vpc-12345',
        SecurityGroupIngress: props.SecurityGroupIngress || [],
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroup'
    };
  }

  // Helper function to create Security Group Ingress test resources
  function createSecurityGroupIngressResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SecurityGroupIngress',
      Properties: {
        GroupId: props.GroupId || 'sg-12345',
        IpProtocol: props.IpProtocol || 'tcp',
        FromPort: props.FromPort !== undefined ? props.FromPort : 22,
        ToPort: props.ToPort !== undefined ? props.ToPort : 22,
        ...props
      },
      LogicalId: props.LogicalId || 'TestSecurityGroupIngress'
    };
  }

  describe('FSx ONTAP FileSystem Tests', () => {
    it('should detect missing preferred subnet ID', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          SecurityGroupIds: ['sg-12345']
        }
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect missing security groups', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: []
        }
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should pass with security groups that are not found in resources', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['sg-12345']
        }
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).toBeNull();
    });

    it('should detect overly permissive SSH access in associated security group', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['EfsSecurityGroup']
        }
      });

      const securityGroup = createSecurityGroupResource({
        LogicalId: 'EfsSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, securityGroup]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should pass with properly restricted SSH access in associated security group', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['EfsSecurityGroup']
        }
      });

      const securityGroup = createSecurityGroupResource({
        LogicalId: 'EfsSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '10.0.0.0/24'
          }
        ]
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, securityGroup]);
      expect(result).toBeNull();
    });
  });

  describe('Security Group Tests', () => {
    it('should detect overly permissive SSH access (0.0.0.0/0)', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect overly permissive API access (port 443)', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 443,
            ToPort: 443,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect overly permissive API access (port 80)', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 80,
            ToPort: 80,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect overly permissive IPv6 CIDR range (::/0)', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIpv6: '::/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect wide CIDR range (less than /24)', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '10.0.0.0/16'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should accept security group with specific CIDR range', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '10.0.0.0/24'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).toBeNull();
    });

    it('should accept security group with source security group reference', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            SourceSecurityGroupId: 'sg-bastion'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).toBeNull();
    });

    it('should skip security group not used by FSx file systems', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'UnrelatedSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).toBeNull();
    });
  });

  describe('Security Group Ingress Tests', () => {
    it('should detect overly permissive SSH access in standalone ingress rule', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup'
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const ingressRule = createSecurityGroupIngressResource({
        GroupId: 'FsxSecurityGroup',
        FromPort: 22,
        ToPort: 22,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(ingressRule, stackName, [securityGroup, fileSystem, ingressRule]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should accept standalone ingress rule with specific CIDR range', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup'
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const ingressRule = createSecurityGroupIngressResource({
        GroupId: 'FsxSecurityGroup',
        FromPort: 22,
        ToPort: 22,
        CidrIp: '10.0.0.0/24'
      });

      const result = rule.evaluate(ingressRule, stackName, [securityGroup, fileSystem, ingressRule]);
      expect(result).toBeNull();
    });

    it('should skip standalone ingress rule for unrelated security group', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup'
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const ingressRule = createSecurityGroupIngressResource({
        GroupId: 'UnrelatedSecurityGroup',
        FromPort: 22,
        ToPort: 22,
        CidrIp: '0.0.0.0/0'
      });

      const result = rule.evaluate(ingressRule, stackName, [securityGroup, fileSystem, ingressRule]);
      expect(result).toBeNull();
    });
  });

  describe('Port Range Tests', () => {
    it('should detect SSH port in range', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 20,
            ToPort: 30,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect API port in range', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 400,
            ToPort: 500,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should detect all protocols (-1) as including SSH and API ports', () => {
      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: '-1',
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const result = rule.evaluate(securityGroup, stackName, [securityGroup, fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing Properties', () => {
      const resource = {
        Type: 'AWS::FSx::FileSystem',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      const result = rule.evaluate(resource, stackName, [resource]);
      expect(result).toBeNull(); // Skip if properties are missing
    });

    it('should handle non-ONTAP file system', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).toBeNull(); // Skip if not ONTAP file system
    });

    it('should ignore non-FSx and non-SecurityGroup resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName, [resource]);
      expect(result).toBeNull();
    });

    it('should detect security issues with intrinsic functions in security group IDs', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: [{ Ref: 'SecurityGroup' }]
        }
      });

      const securityGroup = createSecurityGroupResource({
        LogicalId: 'SecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      // The rule implementation detects the security group with overly permissive access
      const result = rule.evaluate(fileSystem, stackName, [fileSystem, securityGroup]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });

    it('should handle intrinsic functions in CIDR ranges', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: { Ref: 'AllowedCidr' }
          }
        ]
      });

      const result = rule.evaluate(securityGroup, stackName, [fileSystem, securityGroup]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Unable to verify CIDR range at scan time due to intrinsic functions');
    });

    it('should handle intrinsic functions in port ranges', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['FsxSecurityGroup']
        }
      });

      const securityGroup = createSecurityGroupResource({
        LogicalId: 'FsxSecurityGroup',
        SecurityGroupIngress: [
          {
            IpProtocol: 'tcp',
            FromPort: { Ref: 'FromPort' },
            ToPort: { Ref: 'ToPort' },
            CidrIp: '0.0.0.0/0'
          }
        ]
      });

      const result = rule.evaluate(securityGroup, stackName, [fileSystem, securityGroup]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('File system security groups allow SSH or API access from overly permissive sources');
    });
  });
});
