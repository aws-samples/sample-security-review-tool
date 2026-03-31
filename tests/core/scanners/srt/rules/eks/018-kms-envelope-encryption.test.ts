import { describe, it, expect } from 'vitest';
import { EKS018Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/eks/018-kms-envelope-encryption.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('EKS018Rule', () => {
  const rule = new EKS018Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('EKS Cluster tests', () => {
      it('should return a finding if an EKS cluster has no encryption configuration', () => {
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
            // Missing EncryptionConfig
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no encryption configuration');
      });

      it('should return a finding if an EKS cluster has empty encryption configuration', () => {
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
            },
            EncryptionConfig: []
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no encryption configuration');
      });

      it('should return a finding if an EKS cluster has encryption configuration but secrets are not included', () => {
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
            },
            EncryptionConfig: [
              {
                Resources: ['configmaps'],
                Provider: {
                  KeyArn: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
                }
              }
            ]
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('secrets not included in encryption resources');
      });

      it('should return a finding if an EKS cluster has encryption configuration for secrets but no KMS key ARN', () => {
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
            },
            EncryptionConfig: [
              {
                Resources: ['secrets'],
                Provider: {}
              }
            ]
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no KMS key ARN provided');
      });

      it('should return a finding if an EKS cluster references a KMS key that is not properly configured', () => {
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
            EncryptionConfig: [
              {
                Resources: ['secrets'],
                Provider: {
                  KeyArn: { Ref: 'EksKmsKey' }
                }
              }
            ]
          },
          LogicalId: 'TestCluster'
        };

        const kmsKey: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for EKS secrets encryption',
            EnableKeyRotation: false, // Key rotation not enabled
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
                }
              ]
            }
          },
          LogicalId: 'EksKmsKey'
        };

        // Act
        const result = rule.evaluate(cluster, stackName, [cluster, kmsKey]);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.fix).toContain('While references to KMS keys are common');
      });

      it('should not return a finding if an EKS cluster has proper encryption configuration', () => {
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
            },
            EncryptionConfig: [
              {
                Resources: ['secrets'],
                Provider: {
                  KeyArn: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
                }
              }
            ]
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should fail validation for intrinsic functions in EncryptionConfig', () => {
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
            },
            EncryptionConfig: { 'Fn::If': ['UseEncryption', [
              {
                Resources: ['secrets'],
                Provider: {
                  KeyArn: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
                }
              }
            ], []] }
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.issue).toContain('no encryption configuration');
      });

      it('should fail validation for intrinsic functions in KeyArn', () => {
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
            },
            EncryptionConfig: [
              {
                Resources: ['secrets'],
                Provider: {
                  KeyArn: { 'Fn::GetAtt': ['EksKmsKey', 'Arn'] }
                }
              }
            ]
          },
          LogicalId: 'TestCluster'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::EKS::Cluster');
        expect(result?.resourceName).toBe('TestCluster');
        expect(result?.fix).toContain('While references to KMS keys are common');
      });
    });

    describe('KMS Key tests', () => {
      it('should return a finding for an EKS-related KMS key without key rotation enabled', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for EKS secrets encryption',
            EnableKeyRotation: false,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'eks.amazonaws.com'
                  },
                  Action: [
                    'kms:Encrypt',
                    'kms:Decrypt',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*',
                    'kms:DescribeKey'
                  ],
                  Resource: '*'
                }
              ]
            }
          },
          LogicalId: 'EksKmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::KMS::Key');
        expect(result?.resourceName).toBe('EksKmsKey');
        expect(result?.issue).toContain('key rotation not enabled');
      });

      it('should not return a finding for a KMS key without EKS service in key policy', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for S3 encryption', // Changed from EKS to S3
            EnableKeyRotation: true,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
                }
              ]
            },
            // Removed EKS-related tags since they shouldn't affect detection
          },
          LogicalId: 'S3KmsKey' // Changed from EksKmsKey to S3KmsKey
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // Should not detect as EKS-related since we only check direct references and key policy
      });

      it('should not return a finding for an EKS-related KMS key with proper configuration', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for EKS secrets encryption',
            EnableKeyRotation: true,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'eks.amazonaws.com'
                  },
                  Action: [
                    'kms:Encrypt',
                    'kms:Decrypt',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*',
                    'kms:DescribeKey'
                  ],
                  Resource: '*'
                }
              ]
            }
          },
          LogicalId: 'EksKmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding for a non-EKS-related KMS key without key rotation', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for S3 encryption',
            EnableKeyRotation: false,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 's3.amazonaws.com'
                  },
                  Action: [
                    'kms:Encrypt',
                    'kms:Decrypt',
                    'kms:ReEncrypt*',
                    'kms:GenerateDataKey*',
                    'kms:DescribeKey'
                  ],
                  Resource: '*'
                }
              ]
            }
          },
          LogicalId: 'S3KmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not detect EKS-related KMS keys from tags', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for encryption',
            EnableKeyRotation: false,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
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
          LogicalId: 'KmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // Should not detect as EKS-related since we removed tag-based detection
      });

      it('should not detect EKS-related KMS keys from kubernetes.io/cluster tag', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for encryption',
            EnableKeyRotation: false,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
                }
              ]
            },
            Tags: [
              {
                Key: 'kubernetes.io/cluster/test-cluster',
                Value: 'owned'
              }
            ]
          },
          LogicalId: 'KmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // Should not detect as EKS-related since we removed tag-based detection
      });

      it('should not detect EKS-related KMS keys from service tag', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for encryption',
            EnableKeyRotation: false,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
                }
              ]
            },
            Tags: [
              {
                Key: 'Service',
                Value: 'eks'
              }
            ]
          },
          LogicalId: 'KmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // Should not detect as EKS-related since we removed tag-based detection
      });

      it('should fail validation for intrinsic functions in EnableKeyRotation', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for EKS secrets encryption',
            EnableKeyRotation: { Ref: 'EnableKeyRotation' },
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'eks.amazonaws.com'
                  },
                  Action: [
                    'kms:Encrypt',
                    'kms:Decrypt'
                  ],
                  Resource: '*'
                }
              ]
            }
          },
          LogicalId: 'EksKmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::KMS::Key');
        expect(result?.resourceName).toBe('EksKmsKey');
        expect(result?.fix).toContain('Set EnableKeyRotation to an explicit boolean value');
      });

      it('should fail validation for intrinsic functions in KeyPolicy', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for EKS secrets encryption',
            EnableKeyRotation: true,
            KeyPolicy: { 'Fn::If': ['UseEksPolicy', {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'eks.amazonaws.com'
                  },
                  Action: [
                    'kms:Encrypt',
                    'kms:Decrypt'
                  ],
                  Resource: '*'
                }
              ]
            }, {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
                }
              ]
            }] }
          },
          LogicalId: 'EksKmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::KMS::Key');
        expect(result?.resourceName).toBe('EksKmsKey');
        expect(result?.fix).toContain('Set KeyPolicy to explicit values');
      });

      it('should handle intrinsic functions in tag keys', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::KMS::Key',
          Properties: {
            Description: 'KMS key for encryption',
            EnableKeyRotation: true,
            KeyPolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:root'
                  },
                  Action: 'kms:*',
                  Resource: '*'
                }
              ]
            },
            Tags: [
              {
                Key: { Ref: 'TagKey' },
                Value: 'eks'
              }
            ]
          },
          LogicalId: 'KmsKey'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull(); // Should not detect as EKS-related since tag key is an intrinsic function
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
