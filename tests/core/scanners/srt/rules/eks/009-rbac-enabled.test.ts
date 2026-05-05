import { describe, it, expect } from 'vitest';
import { EKS009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/009-rbac-enabled.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS009Rule', () => {
  const rule = new EKS009Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('EKS Cluster tests', () => {
      it('should return a finding if an EKS cluster has no access configuration', () => {
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
        const result = rule.evaluate(resource, stackName, [resource]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no access configuration found');
      });

      it('should return a finding if an EKS cluster has access configuration but no access policies', () => {
        // Arrange
        const cluster: CloudFormationResource = {
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

        const accessEntry: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: 'arn:aws:iam::123456789012:role/developer-role'
            // Missing AccessPolicies
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, accessEntry]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no access policies found');
      });

      it('should return a finding if an EKS cluster has access configuration but no access policies', () => {
        // Arrange
        const cluster: CloudFormationResource = {
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

        const accessEntry: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: 'arn:aws:iam::123456789012:role/developer-role',
            AccessPolicies: [
              {
                PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy',
                AccessScope: {
                  Type: 'namespace',
                  Namespaces: ['default']
                }
              }
            ]
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, accessEntry]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no access policies found');
      });

      it('should recognize aws-auth ConfigMap as valid access configuration', () => {
        // Arrange
        const cluster: CloudFormationResource = {
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

        const configMap: CloudFormationResource = {
          Type: 'Custom::AWSQS-EKSClusterResource',
          Properties: {
            ClusterName: 'TestCluster',
            ConfigMapName: 'aws-auth',
            ConfigMapData: {
              mapRoles: [
                {
                  rolearn: 'arn:aws:iam::123456789012:role/developer-role',
                  username: 'developer',
                  groups: ['system:masters']
                }
              ]
            }
          },
          LogicalId: 'AwsAuthConfigMap'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, configMap]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle intrinsic functions in cluster name', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: { 'Fn::Join': ['-', ['test', 'cluster']] },
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
        const result = rule.evaluate(cluster, stackName, [cluster]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no access configuration found');
      });
    });

    describe('AccessEntry tests', () => {
      it('should return a finding for an AccessEntry without PrincipalArn', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster'
            // Missing PrincipalArn
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessEntry');
        expect(result?.resourceName).toBe('AccessEntry');
        expect(result?.issue).toContain('AccessEntry without PrincipalArn');
      });

      it('should return a finding for an AccessEntry without AccessPolicies', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: 'arn:aws:iam::123456789012:role/developer-role'
            // Missing AccessPolicies
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessEntry');
        expect(result?.resourceName).toBe('AccessEntry');
        expect(result?.issue).toContain('AccessEntry without AccessPolicies');
      });

      it('should return a finding for an AccessEntry with empty AccessPolicies', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: 'arn:aws:iam::123456789012:role/developer-role',
            AccessPolicies: []
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessEntry');
        expect(result?.resourceName).toBe('AccessEntry');
        expect(result?.issue).toContain('EKS cluster does not have role-based access control (RBAC) properly configured');
      });

      it('should return a finding for a properly configured AccessEntry', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: 'arn:aws:iam::123456789012:role/developer-role',
            AccessPolicies: [
              {
                PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy',
                AccessScope: {
                  Type: 'namespace',
                  Namespaces: ['default']
                }
              }
            ]
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessEntry');
        expect(result?.resourceName).toBe('AccessEntry');
        expect(result?.issue).toContain('EKS cluster does not have role-based access control (RBAC) properly configured');
      });

      it('should handle intrinsic functions in PrincipalArn', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: { Ref: 'DeveloperRoleArn' },
            AccessPolicies: [
              {
                PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy',
                AccessScope: {
                  Type: 'namespace',
                  Namespaces: ['default']
                }
              }
            ]
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessEntry');
        expect(result?.resourceName).toBe('AccessEntry');
        expect(result?.fix).toContain('Set PrincipalArn to an explicit value');
      });

      it('should handle intrinsic functions in AccessPolicies', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'TestCluster',
            PrincipalArn: 'arn:aws:iam::123456789012:role/developer-role',
            AccessPolicies: { 'Fn::If': ['IsAdmin', [
              {
                PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy',
                AccessScope: {
                  Type: 'cluster'
                }
              }
            ], [
              {
                PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy',
                AccessScope: {
                  Type: 'namespace',
                  Namespaces: ['default']
                }
              }
            ]] }
          },
          LogicalId: 'AccessEntry'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessEntry');
        expect(result?.resourceName).toBe('AccessEntry');
        expect(result?.fix).toContain('Set AccessPolicies to explicit values');
      });
    });

    describe('AccessPolicy tests', () => {
      it('should return a finding for an AccessPolicy without PolicyArn', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessPolicy',
          Properties: {
            ClusterName: 'TestCluster',
            AccessScope: {
              Type: 'namespace',
              Namespaces: ['default']
            }
            // Missing PolicyArn
          },
          LogicalId: 'AccessPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessPolicy');
        expect(result?.resourceName).toBe('AccessPolicy');
        expect(result?.issue).toContain('AccessPolicy without PolicyArn');
      });

      it('should return a finding for an AccessPolicy without AccessScope', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessPolicy',
          Properties: {
            ClusterName: 'TestCluster',
            PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy'
            // Missing AccessScope
          },
          LogicalId: 'AccessPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessPolicy');
        expect(result?.resourceName).toBe('AccessPolicy');
        expect(result?.issue).toContain('AccessPolicy without AccessScope');
      });

      it('should return a finding for a properly configured AccessPolicy', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessPolicy',
          Properties: {
            ClusterName: 'TestCluster',
            PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy',
            AccessScope: {
              Type: 'namespace',
              Namespaces: ['default']
            }
          },
          LogicalId: 'AccessPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessPolicy');
        expect(result?.resourceName).toBe('AccessPolicy');
        expect(result?.issue).toContain('EKS cluster does not have role-based access control (RBAC) properly configured');
      });

      it('should handle intrinsic functions in PolicyArn', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessPolicy',
          Properties: {
            ClusterName: 'TestCluster',
            PolicyArn: { Ref: 'PolicyArn' },
            AccessScope: {
              Type: 'namespace',
              Namespaces: ['default']
            }
          },
          LogicalId: 'AccessPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessPolicy');
        expect(result?.resourceName).toBe('AccessPolicy');
        expect(result?.fix).toContain('Set PolicyArn to an explicit value');
      });

      it('should handle intrinsic functions in AccessScope', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::AccessPolicy',
          Properties: {
            ClusterName: 'TestCluster',
            PolicyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy',
            AccessScope: { 'Fn::If': ['IsClusterScope', {
              Type: 'cluster'
            }, {
              Type: 'namespace',
              Namespaces: ['default']
            }] }
          },
          LogicalId: 'AccessPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::AccessPolicy');
        expect(result?.resourceName).toBe('AccessPolicy');
        expect(result?.fix).toContain('Set AccessScope to an explicit value');
      });
    });

    it('should return null for non-relevant resources', () => {
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
