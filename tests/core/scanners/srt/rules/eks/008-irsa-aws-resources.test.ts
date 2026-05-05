import { describe, it, expect } from 'vitest';
import { EKS008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/008-irsa-aws-resources.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS008Rule', () => {
  const rule = new EKS008Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('EKS Cluster tests', () => {
      it('should return a finding if an EKS cluster has no OIDC provider configured', () => {
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
            // Missing Identity.OidcIssuerUrl
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName, [resource]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('OIDC provider not configured');
      });

      it('should return a finding if an EKS cluster has OIDC provider but no IAM roles with trust relationships', () => {
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
            },
            Identity: {
              OidcIssuerUrl: 'https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
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
        expect(result?.issue).toContain('no IAM roles with OIDC trust relationships found');
      });

      it('should not return a finding if an EKS cluster has OIDC provider and IAM roles with trust relationships', () => {
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
            },
            Identity: {
              OidcIssuerUrl: 'https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
            }
          },
          LogicalId: 'TestCluster'
        };

        const role: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
                  },
                  Action: 'sts:AssumeRoleWithWebIdentity',
                  Condition: {
                    StringEquals: {
                      'oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub': 'system:serviceaccount:default:my-service-account'
                    }
                  }
                }
              ]
            }
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, role]);

        // Assert
        expect(result).toBeNull();
      });

      it('should recognize an IAM OIDC provider resource as a valid OIDC provider', () => {
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
            // No Identity.OidcIssuerUrl, but we'll have a separate OIDC provider
          },
          LogicalId: 'TestCluster'
        };

        const oidcProvider: CloudFormationResource = {
          Type: 'AWS::IAM::OIDCProvider',
          Properties: {
            Url: 'https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE',
            ClientIdList: ['sts.amazonaws.com'],
            ThumbprintList: ['9e99a48a9960b14926bb7f3b02e22da2b0ab7280'],
            Tags: [
              {
                Key: 'eks:cluster-name',
                Value: 'TestCluster'
              }
            ]
          },
          LogicalId: 'OIDCProvider'
        };

        const role: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
                  },
                  Action: 'sts:AssumeRoleWithWebIdentity',
                  Condition: {
                    StringEquals: {
                      'oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub': 'system:serviceaccount:default:my-service-account'
                    }
                  }
                }
              ]
            }
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, oidcProvider, role]);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle intrinsic functions in Identity.OidcIssuerUrl', () => {
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
            },
            Identity: {
              OidcIssuerUrl: { Ref: 'OidcIssuerUrl' }
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
        expect(result?.issue).toContain('no IAM roles with OIDC trust relationships found');
      });
    });

    describe('IAM Role tests', () => {
      it('should return a finding for an EKS-related IAM role without OIDC trust relationship', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'ec2.amazonaws.com'
                  },
                  Action: 'sts:AssumeRole'
                }
              ]
            },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
            ]
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::IAM::Role');
        expect(result?.resourceName).toBe('PodRole');
        expect(result?.issue).toContain('EKS-related IAM role without OIDC trust relationship');
      });

      it('should not return a finding for an EKS-related IAM role with OIDC trust relationship', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
                  },
                  Action: 'sts:AssumeRoleWithWebIdentity',
                  Condition: {
                    StringEquals: {
                      'oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub': 'system:serviceaccount:default:my-service-account'
                    }
                  }
                }
              ]
            },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
            ]
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for a non-EKS-related IAM role without OIDC trust relationship', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'lambda-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'lambda.amazonaws.com'
                  },
                  Action: 'sts:AssumeRole'
                }
              ]
            },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/AWSLambdaExecute'
            ]
          },
          LogicalId: 'LambdaRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should detect EKS-related roles from tags', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'service-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'ec2.amazonaws.com'
                  },
                  Action: 'sts:AssumeRole'
                }
              ]
            },
            Tags: [
              {
                Key: 'eks:cluster-name',
                Value: 'TestCluster'
              }
            ]
          },
          LogicalId: 'ServiceRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::IAM::Role');
        expect(result?.resourceName).toBe('ServiceRole');
        expect(result?.issue).toContain('EKS-related IAM role without OIDC trust relationship');
      });

      it('should handle intrinsic functions in AssumeRolePolicyDocument', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: { 'Fn::If': ['UseOIDC', {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
                  },
                  Action: 'sts:AssumeRoleWithWebIdentity'
                }
              ]
            }, {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'ec2.amazonaws.com'
                  },
                  Action: 'sts:AssumeRole'
                }
              ]
            }] },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
            ]
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::IAM::Role');
        expect(result?.resourceName).toBe('PodRole');
        expect(result?.issue).toContain('EKS-related IAM role without OIDC trust relationship');
      });

      it('should handle intrinsic functions in Principal.Federated', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: { 'Fn::Join': ['', [
                      'arn:aws:iam::123456789012:oidc-provider/',
                      { Ref: 'OidcProviderUrl' }
                    ]] }
                  },
                  Action: 'sts:AssumeRoleWithWebIdentity'
                }
              ]
            },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
            ]
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::IAM::Role');
        expect(result?.resourceName).toBe('PodRole');
        expect(result?.issue).toContain('EKS-related IAM role without OIDC trust relationship');
      });

      it('should handle intrinsic functions in Condition', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::IAM::Role',
          Properties: {
            RoleName: 'eks-pod-role',
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Federated: 'arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE'
                  },
                  Action: 'sts:AssumeRoleWithWebIdentity',
                  Condition: { 'Fn::If': ['UseStringEquals', {
                    StringEquals: {
                      'oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub': 'system:serviceaccount:default:my-service-account'
                    }
                  }, {
                    StringLike: {
                      'oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub': 'system:serviceaccount:*:*'
                    }
                  }] }
                }
              ]
            },
            ManagedPolicyArns: [
              'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
            ]
          },
          LogicalId: 'PodRole'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
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
