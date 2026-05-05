import { describe, it, expect } from 'vitest';
import { EKS013Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/013-private-endpoint.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS013Rule', () => {
  const rule = new EKS013Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if an EKS cluster has no ResourcesVpcConfig', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role'
          // Missing ResourcesVpcConfig
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have private endpoint properly configured');
    });

    it('should return a finding if an EKS cluster has private endpoint access disabled', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: false,
            EndpointPublicAccess: true
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('private endpoint access is disabled');
    });

    it('should return a finding if an EKS cluster has public access enabled without CIDR restrictions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: true
            // Missing PublicAccessCidrs
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('public access enabled without CIDR restrictions');
    });

    it('should return a finding if an EKS cluster has public access enabled with empty CIDR restrictions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: true,
            PublicAccessCidrs: []
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have private endpoint properly configured');
    });

    it('should return a finding if an EKS cluster has public access enabled with overly permissive CIDRs', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: true,
            PublicAccessCidrs: ['0.0.0.0/0']
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have private endpoint properly configured');
    });

    it('should return a finding if an EKS cluster has public access enabled with IPv6 overly permissive CIDRs', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: true,
            PublicAccessCidrs: ['::/0']
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have private endpoint properly configured');
    });

    it('should not return a finding if an EKS cluster has private access enabled and public access disabled', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: false
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if an EKS cluster has private access enabled and public access restricted with specific CIDRs', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: true,
            PublicAccessCidrs: ['192.168.1.0/24', '10.0.0.0/16']
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.fix).toContain('Set PublicAccessCidrs to explicit values');
    });

    it('should return a finding if EndpointPrivateAccess uses an intrinsic function', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: { Ref: 'EnablePrivateAccess' },
            EndpointPublicAccess: false
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.fix).toContain('Set EndpointPrivateAccess to an explicit boolean value');
    });

    it('should return a finding if EndpointPublicAccess uses an intrinsic function', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: { Ref: 'EnablePublicAccess' }
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.fix).toContain('Set EndpointPublicAccess to an explicit boolean value');
    });

    it('should return a finding if PublicAccessCidrs uses an intrinsic function', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: true,
            PublicAccessCidrs: { 'Fn::Split': [',', { Ref: 'AllowedCIDRs' }] }
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.fix).toContain('Set PublicAccessCidrs to explicit values');
    });

    it('should return null when ResourcesVpcConfig uses intrinsic functions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: { 'Fn::If': ['UseVPC', {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: false
          }, { Ref: 'AWS::NoValue' }] }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for non-EKS resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });
  });
});
