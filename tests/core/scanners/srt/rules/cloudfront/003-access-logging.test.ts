import { describe, it, expect } from 'vitest';
import { CFR003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/003-access-logging.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CFR003Rule', () => {
  const rule = new CFR003Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding with HIGH priority if a CloudFront distribution has no logging', () => {
      // Arrange
      const distribution: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true
          }
        },
        LogicalId: 'TestDistribution'
      };

      const allResources = [distribution];

      // Act
      const result = rule.evaluate(distribution, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('logging not enabled');
      expect(result?.priority).toBe('high');
    });

    it('should return a finding with MEDIUM priority if a CloudFront distribution has logging but no bucket', () => {
      // Arrange
      const distribution: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Logging: {
              Prefix: 'logs/'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      const allResources = [distribution];

      // Act
      const result = rule.evaluate(distribution, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('logging bucket not specified');
      expect(result?.priority).toBe('medium');
    });

    it('should return a finding with MEDIUM priority if a CloudFront distribution has logging but no prefix', () => {
      // Arrange
      const distribution: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Logging: {
              Bucket: 'my-logs-bucket.s3.amazonaws.com'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      const allResources = [distribution];

      // Act
      const result = rule.evaluate(distribution, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('logging prefix not specified');
      expect(result?.priority).toBe('medium');
    });

    it('should return a finding with MEDIUM priority if a CloudFront distribution has logging but the bucket has no lifecycle rules', () => {
      // Arrange
      const distribution: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Logging: {
              Bucket: 'my-logs-bucket.s3.amazonaws.com',
              Prefix: 'logs/'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      const bucket: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-logs-bucket'
          // No lifecycle configuration
        },
        LogicalId: 'LogsBucket'
      };

      const allResources = [distribution, bucket];

      // Act
      const result = rule.evaluate(distribution, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('logging bucket has no lifecycle rules for log retention');
      expect(result?.priority).toBe('medium');
    });

    it('should not return a finding if a CloudFront distribution has proper logging configuration with bucket lifecycle rules', () => {
      // Arrange
      const distribution: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Logging: {
              Bucket: 'my-logs-bucket.s3.amazonaws.com',
              Prefix: 'logs/'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      const bucket: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-logs-bucket',
          LifecycleConfiguration: {
            Rules: [
              {
                Status: 'Enabled',
                ExpirationInDays: 90
              }
            ]
          }
        },
        LogicalId: 'LogsBucket'
      };

      const allResources = [distribution, bucket];

      // Act
      const result = rule.evaluate(distribution, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should properly resolve bucket references', () => {
      // Arrange
      const distribution: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Logging: {
              Bucket: { Ref: 'LogsBucket' },
              Prefix: 'logs/'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      const bucket: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'logs-bucket',
          LifecycleConfiguration: {
            Rules: [
              {
                Status: 'Enabled',
                ExpirationInDays: 90
              }
            ]
          }
        },
        LogicalId: 'LogsBucket'
      };

      const allResources = [distribution, bucket];

      // Act
      const result = rule.evaluate(distribution, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should not evaluate S3 buckets', () => {
      // Arrange
      const bucket: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'my-bucket'
        },
        LogicalId: 'TestBucket'
      };

      const allResources = [bucket];

      // Act
      const result = rule.evaluate(bucket, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });
  });
});
