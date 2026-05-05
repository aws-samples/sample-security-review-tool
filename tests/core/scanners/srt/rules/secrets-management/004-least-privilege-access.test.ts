import { describe, it, expect } from 'vitest';
import { Sec004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/secrets-management/004-least-privilege-access.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Sec004Rule', () => {
  const rule = new Sec004Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::SecretsManager::ResourcePolicy', () => {
      it('should return a finding if a resource policy has wildcard principal', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: '*'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should return a finding if a resource policy has wildcard AWS principal', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: '*'
                  },
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: '*'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should return a finding if a resource policy has wildcard AWS principal in an array', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: [
                      'arn:aws:iam::123456789012:role/specific-role',
                      '*'
                    ]
                  },
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: '*'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should return a finding if a resource policy has wildcard action', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/specific-role'
                  },
                  Action: '*',
                  Resource: '*'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should return a finding if a resource policy has wildcard action in an array', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/specific-role'
                  },
                  Action: [
                    'secretsmanager:GetSecretValue',
                    '*'
                  ],
                  Resource: '*'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should return a finding if a resource policy has wildcard resource', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/specific-role'
                  },
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: '*'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should return a finding if a resource policy has wildcard resource in an array', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/specific-role'
                  },
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: [
                    'arn:aws:secretsmanager:us-west-2:123456789012:secret:specific-secret',
                    '*'
                  ]
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::ResourcePolicy');
        expect(result?.resourceName).toBe('DbPasswordSecretPolicy');
        expect(result?.issue).toContain('Secret has overly permissive access policy');
      });

      it('should not return a finding if a resource policy has specific principal, action, and resource', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/specific-role'
                  },
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:specific-secret'
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a resource policy has specific principal, action, and resource in arrays', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: [
                      'arn:aws:iam::123456789012:role/specific-role-1',
                      'arn:aws:iam::123456789012:role/specific-role-2'
                    ]
                  },
                  Action: [
                    'secretsmanager:GetSecretValue',
                    'secretsmanager:DescribeSecret'
                  ],
                  Resource: [
                    'arn:aws:secretsmanager:us-west-2:123456789012:secret:specific-secret-1',
                    'arn:aws:secretsmanager:us-west-2:123456789012:secret:specific-secret-2'
                  ]
                }
              ]
            })
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a resource policy is provided as an object', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::ResourcePolicy',
          Properties: {
            SecretId: { Ref: 'DbPasswordSecret' },
            ResourcePolicy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/specific-role'
                  },
                  Action: 'secretsmanager:GetSecretValue',
                  Resource: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:specific-secret'
                }
              ]
            }
          },
          LogicalId: 'DbPasswordSecretPolicy'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });
    });

    it('should return null for unsupported resource types', () => {
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
