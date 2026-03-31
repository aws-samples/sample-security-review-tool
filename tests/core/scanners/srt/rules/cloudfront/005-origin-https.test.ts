import { describe, it, expect } from 'vitest';
import { CFR005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/005-origin-https.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CFR005Rule', () => {
  const rule = new CFR005Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return null if a CloudFront distribution has no DistributionConfig', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {},
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if a CloudFront distribution has no Origins', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null if a CloudFront distribution has empty Origins', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: []
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if a CloudFront distribution has a custom origin with HTTP protocol policy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'CustomOrigin',
                DomainName: 'example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'http-only'
                }
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('CloudFront distribution uses insecure HTTP for origin');
    });

    it('should return a finding if a CloudFront distribution has a custom origin with match-viewer protocol policy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'CustomOrigin',
                DomainName: 'example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'match-viewer'
                }
              }
            ],
            DefaultCacheBehavior: {
              ViewerProtocolPolicy: 'allow-all'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('CloudFront distribution uses match-viewer protocol policy');
    });

    it('should not return a finding if a CloudFront distribution has a custom origin with HTTPS protocol policy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'CustomOrigin',
                DomainName: 'example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'https-only'
                }
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a CloudFront distribution has an S3 origin', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'S3Origin',
                DomainName: 'my-bucket.s3.amazonaws.com',
                S3OriginConfig: {
                  OriginAccessIdentity: 'origin-access-identity/cloudfront/E1A2B3C4D5E6F7'
                }
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if a CloudFront distribution has multiple origins with at least one insecure', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'SecureOrigin',
                DomainName: 'secure.example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'https-only'
                }
              },
              {
                Id: 'InsecureOrigin',
                DomainName: 'insecure.example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'http-only'
                }
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('CloudFront distribution uses insecure HTTP for origin');
    });

    it('should return a finding if a CloudFront distribution has a custom origin with outdated TLS version', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'CustomOrigin',
                DomainName: 'example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'https-only',
                  OriginSSLProtocols: ['SSLv3', 'TLSv1']
                }
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('CloudFront distribution uses outdated TLS versions');
    });

    it('should not return a finding if a CloudFront distribution has a custom origin with secure TLS versions', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'CustomOrigin',
                DomainName: 'example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'https-only',
                  OriginSSLProtocols: ['TLSv1.1', 'TLSv1.2']
                }
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for non-CloudFront resources', () => {
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
      expect(result).toBeNull();
    });
  });
});
