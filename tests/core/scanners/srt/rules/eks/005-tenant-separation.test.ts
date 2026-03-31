import { describe, it, expect } from 'vitest';
import { EKS005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/005-tenant-separation.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS005Rule', () => {
  const rule = new EKS005Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('EKS Cluster tests', () => {
      it('should return a finding if a multi-tenant cluster has no identity provider configuration', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'multi-tenant-cluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'MultiTenantCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName, [resource]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('MultiTenantCluster');
        expect(result?.issue).toContain('multi-tenant cluster without identity provider configuration');
      });

      it('should return a finding if a multi-tenant cluster has no namespace separation', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'multi-tenant-cluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'MultiTenantCluster'
        };

        const identityProvider: CloudFormationResource = {
          Type: 'AWS::EKS::IdentityProviderConfig',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            Type: 'oidc',
            IdentityProviderConfigName: 'my-oidc-provider',
            OidcIdentityProviderConfig: {
              ClientId: 'client-id',
              IssuerUrl: 'https://example.com',
              GroupsClaim: 'groups'
            }
          },
          LogicalId: 'OidcProvider'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, identityProvider]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('MultiTenantCluster');
        expect(result?.issue).toContain('multi-tenant cluster without namespace separation');
      });

      it('should not return a finding for a multi-tenant cluster with proper configuration', () => {
        // Arrange
        const cluster: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'multi-tenant-cluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            }
          },
          LogicalId: 'MultiTenantCluster'
        };

        const identityProvider: CloudFormationResource = {
          Type: 'AWS::EKS::IdentityProviderConfig',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            Type: 'oidc',
            IdentityProviderConfigName: 'my-oidc-provider',
            OidcIdentityProviderConfig: {
              ClientId: 'client-id',
              IssuerUrl: 'https://example.com',
              GroupsClaim: 'groups'
            }
          },
          LogicalId: 'OidcProvider'
        };

        const fargateProfile: CloudFormationResource = {
          Type: 'AWS::EKS::FargateProfile',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            PodExecutionRoleArn: 'arn:aws:iam::123456789012:role/fargate-pod-execution-role',
            Selectors: [
              {
                Namespace: 'tenant-a'
              },
              {
                Namespace: 'tenant-b'
              }
            ]
          },
          LogicalId: 'FargateProfile'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, identityProvider, fargateProfile]);

        // Assert
        expect(result).toBeNull();
      });

    it('should return a finding for a non-multi-tenant cluster', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'single-tenant-cluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: false
          }
        },
        LogicalId: 'SingleTenantCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::EKS::Cluster');
      expect(result?.resourceName).toBe('SingleTenantCluster');
      });

      it('should detect multi-tenant cluster from tags', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::Cluster',
          Properties: {
            Name: 'production-cluster',
            RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
            ResourcesVpcConfig: {
              SubnetIds: ['subnet-12345678', 'subnet-87654321'],
              EndpointPrivateAccess: true,
              EndpointPublicAccess: false
            },
            Tags: [
              {
                Key: 'Environment',
                Value: 'Multi-Team'
              }
            ]
          },
          LogicalId: 'ProductionCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName, [resource]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('ProductionCluster');
        expect(result?.issue).toContain('multi-tenant cluster without identity provider configuration');
      });

    it('should return null when cluster name uses intrinsic functions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: { 'Fn::Join': ['-', ['multi', 'tenant', 'cluster']] },
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: false
          }
        },
        LogicalId: 'MultiTenantCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
      });

    it('should return null when tags use intrinsic functions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::EKS::Cluster',
        Properties: {
          Name: 'production-cluster',
          RoleArn: 'arn:aws:iam::123456789012:role/eks-cluster-role',
          ResourcesVpcConfig: {
            SubnetIds: ['subnet-12345678', 'subnet-87654321'],
            EndpointPrivateAccess: true,
            EndpointPublicAccess: false
          },
          Tags: { 'Fn::If': ['IsMultiTenant', [
            {
              Key: 'MultiTenant',
              Value: 'true'
            }
          ], []] }
        },
        LogicalId: 'ProductionCluster'
      };

      // Act
      const result = rule.evaluate(resource, stackName, [resource]);

      // Assert
      expect(result).toBeNull();
      });
    });

    describe('Identity Provider tests', () => {
      it('should return a finding for an OIDC provider without groups claim', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::IdentityProviderConfig',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            Type: 'oidc',
            IdentityProviderConfigName: 'my-oidc-provider',
            OidcIdentityProviderConfig: {
              ClientId: 'client-id',
              IssuerUrl: 'https://example.com'
              // Missing GroupsClaim
            }
          },
          LogicalId: 'OidcProvider'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::IdentityProviderConfig');
        expect(result?.resourceName).toBe('OidcProvider');
        expect(result?.issue).toContain('OIDC provider without groups claim');
      });

      it('should not return a finding for an OIDC provider with groups claim', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::IdentityProviderConfig',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            Type: 'oidc',
            IdentityProviderConfigName: 'my-oidc-provider',
            OidcIdentityProviderConfig: {
              ClientId: 'client-id',
              IssuerUrl: 'https://example.com',
              GroupsClaim: 'groups'
            }
          },
          LogicalId: 'OidcProvider'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle intrinsic functions in OIDC config', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::IdentityProviderConfig',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            Type: 'oidc',
            IdentityProviderConfigName: 'my-oidc-provider',
            OidcIdentityProviderConfig: { 'Fn::If': ['UseOIDC', {
              ClientId: 'client-id',
              IssuerUrl: 'https://example.com'
              // Missing GroupsClaim
            }, { Ref: 'AWS::NoValue' }] }
          },
          LogicalId: 'OidcProvider'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::IdentityProviderConfig');
        expect(result?.resourceName).toBe('OidcProvider');
        expect(result?.issue).toContain('OIDC provider without groups claim');
      });
    });

    describe('Fargate Profile tests', () => {
      it('should return a finding for a Fargate profile without selectors', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::FargateProfile',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            PodExecutionRoleArn: 'arn:aws:iam::123456789012:role/fargate-pod-execution-role'
            // Missing Selectors
          },
          LogicalId: 'FargateProfile'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::FargateProfile');
        expect(result?.resourceName).toBe('FargateProfile');
        expect(result?.issue).toContain('Fargate profile without namespace selectors');
      });

      it('should return a finding for a Fargate profile with empty selectors', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::FargateProfile',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            PodExecutionRoleArn: 'arn:aws:iam::123456789012:role/fargate-pod-execution-role',
            Selectors: []
          },
          LogicalId: 'FargateProfile'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::FargateProfile');
        expect(result?.resourceName).toBe('FargateProfile');
        expect(result?.issue).toContain('Fargate profile without namespace selectors');
      });

      it('should return a finding for a Fargate profile with selectors but no namespace', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::FargateProfile',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            PodExecutionRoleArn: 'arn:aws:iam::123456789012:role/fargate-pod-execution-role',
            Selectors: [
              {
                Labels: {
                  'app': 'frontend'
                }
              }
            ]
          },
          LogicalId: 'FargateProfile'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::FargateProfile');
        expect(result?.resourceName).toBe('FargateProfile');
        expect(result?.issue).toContain('Fargate profile without namespace selectors');
      });

      it('should not return a finding for a Fargate profile with namespace selectors', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::FargateProfile',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            PodExecutionRoleArn: 'arn:aws:iam::123456789012:role/fargate-pod-execution-role',
            Selectors: [
              {
                Namespace: 'tenant-a'
              }
            ]
          },
          LogicalId: 'FargateProfile'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle intrinsic functions in selectors', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::EKS::FargateProfile',
          Properties: {
            ClusterName: 'multi-tenant-cluster',
            PodExecutionRoleArn: 'arn:aws:iam::123456789012:role/fargate-pod-execution-role',
            Selectors: { 'Fn::If': ['UseNamespaces', [
              {
                Namespace: { Ref: 'TenantNamespace' }
              }
            ], []] }
          },
          LogicalId: 'FargateProfile'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::FargateProfile');
        expect(result?.resourceName).toBe('FargateProfile');
        expect(result?.issue).toContain('Fargate profile without namespace selectors');
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
