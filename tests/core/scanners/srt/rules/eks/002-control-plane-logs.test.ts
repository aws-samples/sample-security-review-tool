import { describe, it, expect } from 'vitest';
import { EKS002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/002-control-plane-logs.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS002Rule', () => {
  const rule = new EKS002Rule();
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
      expect(result?.issue).toContain('EKS cluster does not have control plane logs enabled');
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
      expect(result?.issue).toContain('EKS cluster does not have control plane logs enabled');
    });

    it('should return a finding if an EKS cluster is missing some log types', () => {
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
                Types: ['api', 'audit'] // Missing controllerManager, scheduler, authenticator
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
      expect(result?.issue).toContain('missing log types');
      expect(result?.issue).toContain('controllerManager');
      expect(result?.issue).toContain('scheduler');
      expect(result?.issue).toContain('authenticator');
    });

    it('should not return a finding if an EKS cluster has all required log types enabled', () => {
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
      expect(result?.issue).toContain('EKS cluster does not have control plane logs enabled');
      expect(result?.fix).toContain('Set Logging to explicit values rather than using CloudFormation functions');
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
      expect(result?.issue).toContain('EKS cluster does not have control plane logs enabled');
    });

    it('should handle intrinsic functions in Enabled property', () => {
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
                Enabled: { Ref: 'EnableLogging' },
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
      expect(result?.issue).toContain('EKS cluster does not have control plane logs enabled');
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
                Types: { 'Fn::Split': [',', 'api,audit,authenticator,controllerManager,scheduler'] }
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
      expect(result?.issue).toContain('EKS cluster does not have control plane logs enabled');
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
