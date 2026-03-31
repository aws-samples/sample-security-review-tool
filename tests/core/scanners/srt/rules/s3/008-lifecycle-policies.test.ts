import { describe, it, expect } from 'vitest';
import { S3008Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/008-lifecycle-policies.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('S3008Rule', () => {
  const rule = new S3008Rule();
  const stackName = 'test-stack';

  describe('rule properties', () => {
    it('should have the correct ID', () => {
      expect(rule.id).toBe('S3-008');
    });

    it('should have HIGH priority', () => {
      expect(rule.priority).toBe('HIGH');
    });

    it('should apply to S3 buckets', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(true);
      expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
    });
  });

  describe('evaluate', () => {
    it('should return null for non-S3 resources', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs14.x',
          Code: {
            S3Bucket: 'my-bucket',
            S3Key: 'my-key'
          }
        },
        LogicalId: 'TestFunction'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if a bucket has lifecycle configuration', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket',
          LifecycleConfiguration: {
            Rules: [
              {
                Status: 'Enabled',
                ExpirationInDays: 365,
                Id: 'ExpireOldObjects'
              }
            ]
          }
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if a bucket has no lifecycle configuration', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::S3::Bucket');
      expect(result?.resourceName).toBe('TestBucket');
      expect(result?.issue).toContain('S3 bucket lacks lifecycle policy');
      expect(result?.fix).toContain('Configure a lifecycle policy');
    });

    it('should return a finding if a bucket has empty lifecycle configuration', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket',
          LifecycleConfiguration: null
        },
        LogicalId: 'MyBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::S3::Bucket');
      expect(result?.resourceName).toBe('MyBucket');
      expect(result?.issue).toContain('S3 bucket lacks lifecycle policy');
      expect(result?.fix).toContain('Configure a lifecycle policy');
    });

    it('should return a finding if a bucket has lifecycle configuration with intrinsic function', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket',
          LifecycleConfiguration: { Ref: 'LifecycleConfigurationParameter' }
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::S3::Bucket');
      expect(result?.resourceName).toBe('TestBucket');
      expect(result?.issue).toContain('S3 bucket lacks lifecycle policy');
      expect(result?.fix).toContain('Use explicit configuration instead of CloudFormation intrinsic functions');
    });

    it('should return a finding if a bucket has lifecycle configuration with Fn::GetAtt', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket',
          LifecycleConfiguration: { 'Fn::GetAtt': ['LifecycleConfig', 'Configuration'] }
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::S3::Bucket');
      expect(result?.resourceName).toBe('TestBucket');
      expect(result?.issue).toContain('S3 bucket lacks lifecycle policy');
      expect(result?.fix).toContain('Use explicit configuration instead of CloudFormation intrinsic functions');
    });

    it('should return a finding if a bucket has lifecycle configuration with Fn::If', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket',
          LifecycleConfiguration: { 
            'Fn::If': [
              'EnableLifecycle',
              {
                Rules: [
                  {
                    Status: 'Enabled',
                    ExpirationInDays: 365,
                    Id: 'ExpireOldObjects'
                  }
                ]
              },
              { Ref: 'AWS::NoValue' }
            ]
          }
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::S3::Bucket');
      expect(result?.resourceName).toBe('TestBucket');
      expect(result?.issue).toContain('S3 bucket lacks lifecycle policy');
      expect(result?.fix).toContain('Use explicit configuration instead of CloudFormation intrinsic functions');
    });

    it('should return null if a bucket has lifecycle configuration with empty rules array', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket',
          LifecycleConfiguration: {
            Rules: []
          }
        },
        LogicalId: 'TestBucket'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      // Even though the rules array is empty, the LifecycleConfiguration exists and is resolved
      // The rule only checks for existence, not content quality
      expect(result).toBeNull();
    });
  });
});
