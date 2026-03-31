import { describe, it, expect } from 'vitest';
import { Sec003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/secrets-management/003-kms-encryption.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Sec003Rule', () => {
  const rule = new Sec003Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::SecretsManager::Secret', () => {
      it('should return a finding if a secret has no KMS key ID', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
            Description: 'Database password for the application',
            SecretString: '{"username":"admin","password":"secret"}'
          },
          LogicalId: 'DbPasswordSecret'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::Secret');
        expect(result?.resourceName).toBe('DbPasswordSecret');
        expect(result?.issue).toContain('Secret does not use KMS encryption');
      });

      it('should return a finding if a secret uses an AWS-managed KMS key', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
            Description: 'Database password for the application',
            SecretString: '{"username":"admin","password":"secret"}',
            KmsKeyId: 'aws/secretsmanager'
          },
          LogicalId: 'DbPasswordSecret'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::Secret');
        expect(result?.resourceName).toBe('DbPasswordSecret');
        expect(result?.issue).toContain('Secret uses an AWS-managed KMS key instead of a customer-managed key');
      });

      it('should return a finding if a secret uses an AWS-managed KMS key ARN', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
            Description: 'Database password for the application',
            SecretString: '{"username":"admin","password":"secret"}',
            KmsKeyId: 'arn:aws:kms:us-west-2:123456789012:key/aws/secretsmanager'
          },
          LogicalId: 'DbPasswordSecret'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::SecretsManager::Secret');
        expect(result?.resourceName).toBe('DbPasswordSecret');
        expect(result?.issue).toContain('Secret uses an AWS-managed KMS key instead of a customer-managed key');
      });

      it('should not return a finding if a secret uses a customer-managed KMS key', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
            Description: 'Database password for the application',
            SecretString: '{"username":"admin","password":"secret"}',
            KmsKeyId: 'arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
          },
          LogicalId: 'DbPasswordSecret'
        };

        // Act
        const result = rule.evaluate(resource, stackName);

        // Assert
        expect(result).toBeNull();
      });

      it('should not return a finding if a secret uses a reference to a customer-managed KMS key', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
            Description: 'Database password for the application',
            SecretString: '{"username":"admin","password":"secret"}',
            KmsKeyId: { Ref: 'MyKmsKey' }
          },
          LogicalId: 'DbPasswordSecret'
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
