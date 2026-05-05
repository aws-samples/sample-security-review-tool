import { describe, it, expect } from 'vitest';
import { FSx002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/fsx/002-vpc-endpoints.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('FSx002Rule - VPC Endpoints Tests', () => {
  const rule = new FSx002Rule();
  const stackName = 'test-stack';

  // Helper function to create FSx FileSystem test resources
  function createFSxFileSystemResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::FSx::FileSystem',
      Properties: {
        FileSystemType: props.FileSystemType || 'WINDOWS',
        VpcId: props.VpcId || 'vpc-12345',
        ...props
      },
      LogicalId: props.LogicalId || 'TestFileSystem'
    };
  }

  // Helper function to create VPC Endpoint test resources
  function createVPCEndpointResource(props: Record<string, any> = {}): CloudFormationResource {
    return {
      Type: 'AWS::EC2::VPCEndpoint',
      Properties: {
        VpcId: props.VpcId || 'vpc-12345',
        ServiceName: props.ServiceName || 'com.amazonaws.us-east-1.fsx',
        VpcEndpointType: props.VpcEndpointType || 'Interface',
        PrivateDnsEnabled: props.PrivateDnsEnabled !== undefined ? props.PrivateDnsEnabled : true,
        SecurityGroupIds: props.SecurityGroupIds || ['sg-12345'],
        ...props
      },
      LogicalId: props.LogicalId || 'TestVPCEndpoint'
    };
  }

  describe('FSx FileSystem Tests', () => {
    it('should detect missing VPC endpoints for FSx', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          VpcConfiguration: {
            VpcId: 'vpc-12345'
          }
        }
      });

      // No VPC endpoints in the resources
      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
    });

    it('should pass with FSx VPC endpoint in the same VPC', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          VpcConfiguration: {
            VpcId: 'vpc-12345'
          }
        }
      });

      const vpcEndpoint = createVPCEndpointResource({
        VpcId: 'vpc-12345',
        ServiceName: 'com.amazonaws.us-east-1.fsx'
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpcEndpoint]);
      expect(result).toBeNull();
    });

    it('should detect FSx file system without VPC ID', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {}
      });

      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).toBeNull(); // Skip if we can't determine the VPC ID
    });

    describe('Lustre File System Tests', () => {
      it('should detect missing VPC endpoints for Lustre file system', () => {
        const fileSystem = createFSxFileSystemResource({
          FileSystemType: 'LUSTRE',
          VpcId: 'vpc-12345',
          LustreConfiguration: {
            DeploymentType: 'PERSISTENT_1'
          }
        });

        // No VPC endpoints in the resources
        const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
      });

      it('should pass with FSx VPC endpoint for Lustre file system', () => {
        const fileSystem = createFSxFileSystemResource({
          FileSystemType: 'LUSTRE',
          VpcId: 'vpc-12345',
          LustreConfiguration: {
            DeploymentType: 'PERSISTENT_1'
          }
        });

        const vpcEndpoint = createVPCEndpointResource({
          VpcId: 'vpc-12345',
          ServiceName: 'com.amazonaws.us-east-1.fsx'
        });

        const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpcEndpoint]);
        expect(result).toBeNull();
      });
    });

    describe('ONTAP File System Tests', () => {
      it('should detect missing VPC endpoints for ONTAP file system', () => {
        const fileSystem = createFSxFileSystemResource({
          FileSystemType: 'ONTAP',
          VpcId: 'vpc-12345',
          OntapConfiguration: {
            PreferredSubnetId: 'subnet-12345'
          }
        });

        // No VPC endpoints in the resources
        const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
      });

      it('should pass with FSx VPC endpoint for ONTAP file system', () => {
        const fileSystem = createFSxFileSystemResource({
          FileSystemType: 'ONTAP',
          VpcId: 'vpc-12345',
          OntapConfiguration: {
            PreferredSubnetId: 'subnet-12345'
          }
        });

        const vpcEndpoint = createVPCEndpointResource({
          VpcId: 'vpc-12345',
          ServiceName: 'com.amazonaws.us-east-1.fsx'
        });

        const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpcEndpoint]);
        expect(result).toBeNull();
      });
    });

    describe('OpenZFS File System Tests', () => {
      it('should detect missing VPC endpoints for OpenZFS file system', () => {
        const fileSystem = createFSxFileSystemResource({
          FileSystemType: 'OPENZFS',
          VpcId: 'vpc-12345',
          OpenZFSConfiguration: {
            DeploymentType: 'SINGLE_AZ_1'
          }
        });

        // No VPC endpoints in the resources
        const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
        expect(result).not.toBeNull();
        expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
      });

      it('should pass with FSx VPC endpoint for OpenZFS file system', () => {
        const fileSystem = createFSxFileSystemResource({
          FileSystemType: 'OPENZFS',
          VpcId: 'vpc-12345',
          OpenZFSConfiguration: {
            DeploymentType: 'SINGLE_AZ_1'
          }
        });

        const vpcEndpoint = createVPCEndpointResource({
          VpcId: 'vpc-12345',
          ServiceName: 'com.amazonaws.us-east-1.fsx'
        });

        const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpcEndpoint]);
        expect(result).toBeNull();
      });
    });
  });

  describe('VPC Endpoint Tests', () => {
    it('should detect non-Interface endpoint type for FSx', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: 'com.amazonaws.us-east-1.fsx',
        VpcEndpointType: 'Gateway'
      });

      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
    });

    it('should detect private DNS disabled for FSx endpoint', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: 'com.amazonaws.us-east-1.fsx',
        PrivateDnsEnabled: false
      });

      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
    });

    it('should detect missing security groups for FSx endpoint', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: 'com.amazonaws.us-east-1.fsx',
        SecurityGroupIds: []
      });

      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
    });

    it('should pass with properly configured FSx endpoint', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: 'com.amazonaws.us-east-1.fsx',
        VpcEndpointType: 'Interface',
        PrivateDnsEnabled: true,
        SecurityGroupIds: ['sg-12345']
      });

      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull();
    });

    it('should skip non-FSx VPC endpoints', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: 'com.amazonaws.us-east-1.s3',
        VpcEndpointType: 'Gateway'
      });

      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull();
    });

    it('should detect FSx endpoint with Fn::Sub', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: {
          'Fn::Sub': 'com.amazonaws.${AWS::Region}.fsx'
        }
      });

      // Should pass since it's properly configured
      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull();
    });

    it('should detect FSx endpoint with Fn::Join', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: {
          'Fn::Join': [
            '',
            ['com.amazonaws.', { 'Ref': 'AWS::Region' }, '.fsx']
          ]
        }
      });

      // Should pass since it's properly configured
      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull();
    });

    it('should handle unresolvable intrinsic functions in ServiceName', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: {
          'Fn::ImportValue': 'ExportedFSxServiceName'
        }
      });

      // Should skip since we can't resolve the service name
      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull();
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

    it('should handle missing ServiceName in VPC endpoint', () => {
      const vpcEndpoint = {
        Type: 'AWS::EC2::VPCEndpoint',
        Properties: {
          VpcId: 'vpc-12345',
          VpcEndpointType: 'Interface',
          PrivateDnsEnabled: true,
          SecurityGroupIds: ['sg-12345']
        },
        LogicalId: 'TestVPCEndpoint'
      } as CloudFormationResource;

      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull(); // Skip if ServiceName is missing
    });

    it('should ignore non-FSx and non-VPCEndpoint resources', () => {
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

    it('should handle intrinsic functions in VpcId for FSx FileSystem', () => {
      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          VpcConfiguration: {
            VpcId: { Ref: 'VpcId' }
          }
        }
      });

      // Should skip since we can't resolve the VPC ID
      const result = rule.evaluate(fileSystem, stackName, [fileSystem]);
      expect(result).toBeNull();
    });

    it('should handle intrinsic functions in SecurityGroupIds for VPC endpoint', () => {
      const vpcEndpoint = createVPCEndpointResource({
        ServiceName: 'com.amazonaws.us-east-1.fsx',
        SecurityGroupIds: { Ref: 'SecurityGroups' }
      });

      // The rule implementation treats this as a valid configuration since the resolver
      // considers the reference to potentially be valid security groups
      const result = rule.evaluate(vpcEndpoint, stackName);
      expect(result).toBeNull();
    });
  });

  describe('CloudFormation Resolver Tests', () => {
    it('should handle FSx FileSystem with VPC ID reference', () => {
      const vpc = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVPC'
      } as CloudFormationResource;

      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          VpcConfiguration: {
            VpcId: { Ref: 'TestVPC' }
          }
        }
      });

      const vpcEndpoint = createVPCEndpointResource({
        VpcId: { Ref: 'TestVPC' },
        ServiceName: 'com.amazonaws.us-east-1.fsx'
      });

      // Should pass since the VPC endpoint is in the same VPC
      const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpc, vpcEndpoint]);
      expect(result).toBeNull();
    });

    it('should handle FSx FileSystem with VPC ID reference but no matching endpoint', () => {
      const vpc = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVPC'
      } as CloudFormationResource;

      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          VpcConfiguration: {
            VpcId: { Ref: 'TestVPC' }
          }
        }
      });

      // No VPC endpoint in the resources
      const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpc]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
    });

    it('should handle FSx FileSystem with VPC ID reference and endpoint with different VPC', () => {
      const vpc1 = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.0.0.0/16'
        },
        LogicalId: 'TestVPC1'
      } as CloudFormationResource;

      const vpc2 = {
        Type: 'AWS::EC2::VPC',
        Properties: {
          CidrBlock: '10.1.0.0/16'
        },
        LogicalId: 'TestVPC2'
      } as CloudFormationResource;

      const fileSystem = createFSxFileSystemResource({
        FileSystemType: 'WINDOWS',
        WindowsConfiguration: {
          VpcConfiguration: {
            VpcId: { Ref: 'TestVPC1' }
          }
        }
      });

      const vpcEndpoint = createVPCEndpointResource({
        VpcId: { Ref: 'TestVPC2' },
        ServiceName: 'com.amazonaws.us-east-1.fsx'
      });

      // Should fail since the VPC endpoint is in a different VPC
      const result = rule.evaluate(fileSystem, stackName, [fileSystem, vpc1, vpc2, vpcEndpoint]);
      expect(result).not.toBeNull();
      expect(result?.issue).toContain('FSx file system does not use VPC endpoints for secure connectivity');
    });
  });
});
