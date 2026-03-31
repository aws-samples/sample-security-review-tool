import { describe, it, expect } from 'vitest';
import { CFR002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/002-waf-protection';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CFR002Rule', () => {
  const rule = new CFR002Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if a CloudFront distribution has no DistributionConfig', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {},
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('missing DistributionConfig');
    });

    it('should return a finding if a public web CloudFront distribution has no WebACLId', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            DefaultRootObject: 'index.html',
            Origins: [
              {
                Id: 'S3Origin',
                DomainName: 'my-bucket.s3.amazonaws.com',
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
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('public-facing web distribution without WAF protection');
    });

    it('should not return a finding if a CloudFront distribution has WebACLId', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            WebACLId: 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/ExampleWebACL/1234abcd-12ab-34cd-56ef-1234567890ab'
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a CloudFront distribution has WebACLId as a Ref', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            WebACLId: { Ref: 'MyWebACL' }
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should return a finding if a CloudFront distribution has web content path patterns', () => {
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
            ],
            DefaultCacheBehavior: {
              TargetOriginId: 'CustomOrigin',
              ViewerProtocolPolicy: 'https-only'
            },
            CacheBehaviors: [
              {
                PathPattern: '*.html',
                TargetOriginId: 'CustomOrigin',
                ViewerProtocolPolicy: 'https-only'
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
      expect(result?.issue).toContain('public-facing web distribution without WAF protection');
    });

    it('should return a finding if a CloudFront distribution allows POST/PUT methods', () => {
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
            ],
            DefaultCacheBehavior: {
              TargetOriginId: 'CustomOrigin',
              ViewerProtocolPolicy: 'https-only',
              AllowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'POST', 'PATCH', 'DELETE']
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
      expect(result?.issue).toContain('public-facing web distribution without WAF protection');
    });

    it('should return a finding if a CloudFront distribution has DefaultRootObject', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            DefaultRootObject: 'index.html'
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
      expect(result?.issue).toContain('public-facing web distribution without WAF protection');
    });

    it('should not return a finding if a CloudFront distribution is private', () => {
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
            ],
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ViewerProtocolPolicy: 'https-only'
            }
          }
        },
        LogicalId: 'TestDistribution'
      };

      // Act
      const result = rule.evaluate(resource, stackName);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a CloudFront distribution is not serving web content', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'CustomOrigin',
                DomainName: 'api.example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'https-only'
                }
              }
            ],
            DefaultCacheBehavior: {
              TargetOriginId: 'CustomOrigin',
              ViewerProtocolPolicy: 'https-only',
              PathPattern: '/api/*',
              AllowedMethods: ['GET', 'HEAD', 'OPTIONS']
            }
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
