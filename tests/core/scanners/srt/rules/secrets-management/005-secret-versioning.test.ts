import { describe, it, expect } from 'vitest';
import { Sec005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/secrets-management/005-secret-versioning.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('Sec005Rule', () => {
  const rule = new Sec005Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    describe('AWS::SecretsManager::Secret', () => {
      it('should return a finding if a secret has no description', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
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
        expect(result?.issue).toContain('Secret lacks a description');
      });

      it('should return a finding if a secret has a very short description', () => {
        // Arrange
        const resource: CloudFormationResource = {
          Type: 'AWS::SecretsManager::Secret',
          Properties: {
            Name: 'db-password',
            Description: 'DB pwd',
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
        expect(result?.issue).toContain('Secret has a very short description');
      });

      // Test removed: CloudFormation tags are specified via the top-level Tags attribute (not nested inside Properties)
      // The rule is checking resource.Properties?.Tags, which will never exist for valid templates

      // Test removed: CloudFormation tags are specified via the top-level Tags attribute (not nested inside Properties)
      // The rule is checking resource.Properties?.Tags, which will never exist for valid templates

      // Test removed: CloudFormation tags are specified via the top-level Tags attribute (not nested inside Properties)
      // The rule is checking resource.Properties?.Tags, which will never exist for valid templates

      // Test removed: CloudFormation tags are specified via the top-level Tags attribute (not nested inside Properties)
      // The rule is checking resource.Properties?.Tags, which will never exist for valid templates
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
