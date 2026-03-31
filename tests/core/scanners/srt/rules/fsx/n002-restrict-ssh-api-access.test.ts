import { describe, it, expect } from 'vitest';
import { FSxN002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/fsx/n002-restrict-ssh-api-access.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('FSxN002Rule - Restrict SSH and API Access Tests', () => {
  const rule = new FSxN002Rule();
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

  // Helper function to create Subnet test resources
  function createSubnetResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::Subnet',
      Properties: {
        VpcId: props.VpcId || 'vpc-12345',
        CidrBlock: props.CidrBlock || '10.0.0.0/24',
        MapPublicIpOnLaunch: props.MapPublicIpOnLaunch !== undefined ? props.MapPublicIpOnLaunch : false,
        ...props
      },
      LogicalId: props.LogicalId || 'TestSubnet'
    };
  }

  // Helper function to create Route Table test resources
  function createRouteTableResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::RouteTable',
      Properties: {
        VpcId: props.VpcId || 'vpc-12345',
        ...props
      },
      LogicalId: props.LogicalId || 'TestRouteTable'
    };
  }

  // Helper function to create Route test resources
  function createRouteResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::Route',
      Properties: {
        RouteTableId: props.RouteTableId || 'TestRouteTable',
        DestinationCidrBlock: props.DestinationCidrBlock || '0.0.0.0/0',
        GatewayId: props.GatewayId || 'igw-12345',
        ...props
      },
      LogicalId: props.LogicalId || 'TestRoute'
    };
  }

  // Helper function to create Subnet Route Table Association test resources
  function createSubnetRouteTableAssociationResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::SubnetRouteTableAssociation',
      Properties: {
        SubnetId: props.SubnetId || 'subnet-12345',
        RouteTableId: props.RouteTableId || 'TestRouteTable',
        ...props
      },
      LogicalId: props.LogicalId || 'TestSubnetRouteTableAssociation'
    };
  }

  // Helper function to create Internet Gateway test resources
  function createInternetGatewayResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::InternetGateway',
      Properties: {
        ...props
      },
      LogicalId: props.LogicalId || 'TestInternetGateway'
    };
  }

  describe('FSx ONTAP FileSystem Tests', () => {
    it('should detect missing SVMs', () => {
      const fileSystem = createFSxFileSystemResource();

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should detect missing security groups', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: []
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: 'TestFileSystem'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should detect public subnet', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['sg-12345']
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: 'TestFileSystem'
      });

      const subnet = createSubnetResource({
        LogicalId: 'subnet-12345',
        MapPublicIpOnLaunch: true
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm, subnet]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should detect subnet with internet gateway route', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['sg-12345']
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: 'TestFileSystem'
      });

      const subnet = createSubnetResource({
        LogicalId: 'subnet-12345'
      });

      const routeTable = createRouteTableResource({
        LogicalId: 'TestRouteTable'
      });

      const route = createRouteResource({
        RouteTableId: 'TestRouteTable',
        GatewayId: 'TestInternetGateway'
      });

      const association = createSubnetRouteTableAssociationResource({
        SubnetId: 'subnet-12345',
        RouteTableId: 'TestRouteTable'
      });

      const internetGateway = createInternetGatewayResource({
        LogicalId: 'TestInternetGateway'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm, subnet, routeTable, route, association, internetGateway]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should pass with private subnet and security groups', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['sg-12345']
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: 'TestFileSystem'
      });

      const subnet = createSubnetResource({
        LogicalId: 'subnet-12345'
      });

      const routeTable = createRouteTableResource({
        LogicalId: 'TestRouteTable'
      });

      const association = createSubnetRouteTableAssociationResource({
        SubnetId: 'subnet-12345',
        RouteTableId: 'TestRouteTable'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm, subnet, routeTable, association]);
      expect(result).toBeNull();
    });
  });

  describe('Storage Virtual Machine Tests', () => {
    it('should detect literal password', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: 'Password123'
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should detect missing Active Directory configuration', () => {
      const svm = createFSxStorageVirtualMachineResource();

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should detect public management endpoint', () => {
      const svm = createFSxStorageVirtualMachineResource({
        ActiveDirectoryConfiguration: {
          NetBiosName: 'TESTVM'
        },
        Endpoints: {
          Management: {
            IpAddressType: 'PUBLIC'
          }
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('SSH and API access to file system and SVMs is not restricted to appropriate entities');
    });

    it('should pass with Active Directory configuration', () => {
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
      expect(result).toBeNull();
    });

    it('should pass with secure password reference', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: { 'Ref': 'SecurePassword' }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).toBeNull();
    });

    it('should pass with SSM parameter reference', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: {
          'Fn::Sub': '{{resolve:ssm:/fsx/admin-password:1}}'
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).toBeNull();
    });

    it('should pass with Secrets Manager reference', () => {
      const svm = createFSxStorageVirtualMachineResource({
        SvmAdminPassword: {
          'Fn::Join': ['', ['{{resolve:secretsmanager:', { 'Ref': 'AdminSecret' }, ':SecretString:password}}']]
        }
      });

      const result = rule.evaluate(svm, stackName);
      expect(result).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should detect issues with missing Properties', () => {
      const resource = {
        Type: 'AWS::FSx::FileSystem',
        LogicalId: 'MissingProperties'
      } as CloudFormationResource;

      // The rule implementation treats missing properties as unresolvable values
      const result = rule.evaluate(resource, stackName, [resource]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Unable to verify file system type at scan time');
    });

    it('should handle non-ONTAP file system', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).toBeNull(); // Skip if not ONTAP file system
    });

    it('should handle missing OntapConfiguration', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'ONTAP',
        OntapConfiguration: undefined
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
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

    it('should handle unresolvable file system type', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: { Ref: 'FileSystemType' }
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Unable to verify file system type at scan time');
    });

    it('should handle intrinsic functions in SVM references', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['sg-12345']
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: { 'Fn::GetAtt': ['TestFileSystem', 'FileSystemId'] }
      });

      const subnet = createSubnetResource({
        LogicalId: 'subnet-12345'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm, subnet]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Found unresolvable references');
    });

    it('should handle intrinsic functions in subnet references', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: { Ref: 'SubnetId' },
          SecurityGroupIds: ['sg-12345']
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: 'TestFileSystem'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Found unresolvable subnet references');
    });

    it('should handle CDK-specific token patterns', () => {
      const fileSystem = createFSxFileSystemResource({
        OntapConfiguration: {
          PreferredSubnetId: 'subnet-12345',
          SecurityGroupIds: ['sg-12345']
        }
      });

      const svm = createFSxStorageVirtualMachineResource({
        FileSystemId: {
          'Fn::Join': [
            '',
            [
              '${Token[',
              { 'Ref': 'TestFileSystem' },
              '.FileSystemId.12345]}'
            ]
          ]
        }
      });

      const subnet = createSubnetResource({
        LogicalId: 'subnet-12345'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, svm, subnet]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('Found unresolvable references');
    });
  });
});
