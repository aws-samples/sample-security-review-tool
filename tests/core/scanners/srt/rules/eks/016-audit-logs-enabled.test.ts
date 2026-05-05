import { describe, it, expect } from 'vitest';
import { EKS016Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/016-audit-logs-enabled.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS016Rule', () => {
  const rule = new EKS016Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if an EKS cluster has no logging configuration', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
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
      expect(result?.issue).toContain('EKS cluster does not have audit logs enabled');
    });

    it('should return a finding if an EKS cluster has logging disabled', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: {
            ClusterLogging: [
              {
                Enabled: false,
                Types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
              }
            ]
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
      expect(result?.issue).toContain('EKS cluster does not have audit logs enabled');
    });

    it('should return a finding if an EKS cluster is missing audit log type', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: {
            ClusterLogging: [
              {
                Enabled: true,
                Types: ['api', 'authenticator', 'controllerManager', 'scheduler'] // Missing audit
              }
            ]
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
      expect(result?.issue).toContain('EKS cluster does not have audit logs enabled');
    });

    it('should not return a finding if an EKS cluster has audit logs enabled', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: {
            ClusterLogging: [
              {
                Enabled: true,
                Types: ['audit']
              }
            ]
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if an EKS cluster has all log types enabled including audit', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: {
            ClusterLogging: [
              {
                Enabled: true,
                Types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
              }
            ]
          }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle intrinsic functions in Logging property', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: { 'Fn::If': ['EnableLogging', {
            ClusterLogging: [
              {
                Enabled: true,
                Types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
              }
            ]
          }, { Ref: 'AWS::NoValue' }] }
        },
        LogicalId: 'TestCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('TestCluster');
      expect(result?.issue).toContain('EKS cluster does not have audit logs enabled');
    });

    it('should handle intrinsic functions in ClusterLogging property', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: {
            ClusterLogging: { 'Fn::If': ['EnableLogging', [
              {
                Enabled: true,
                Types: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
              }
            ], []] }
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
      expect(result?.issue).toContain('EKS cluster does not have audit logs enabled');
    });

    it('should handle intrinsic functions in Types property', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'TestCluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321']
          },
          Logging: {
            ClusterLogging: [
              {
                Enabled: true,
                Types: { 'Fn::Split': [',', { Ref: 'LogTypes' }] }
              }
            ]
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
      expect(result?.issue).toContain('EKS cluster does not have audit logs enabled');
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
