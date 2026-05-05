import { describe, it, expect } from 'vitest';
import { CFR006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/006-origin-access-control.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CFR006Rule', () => {
  const rule = new CFR006Rule();
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

    it('should return null if a CloudFront distribution has no S3 origins', () => {
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

    it('should return a finding if a CloudFront distribution has an S3 origin without OAI or OAC', () => {
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
                S3OriginConfig: {}
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
      expect(result?.issue).toContain('CloudFront S3 origin lacks Origin Access Control');
    });

    it('should not return a finding if a CloudFront distribution has an S3 origin with OAI', () => {
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
      expect(result).not.toBeNull();
      expect(result?.priority).toBe('medium');
      expect(result?.issue).toContain('uses legacy Origin Access Identity');
    });

    it('should not return a finding if a CloudFront distribution has an S3 origin with OAC at origin level', () => {
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
                OriginAccessControlId: 'E1A2B3C4D5E6F7'
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

    it('should handle different S3 domain formats', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'S3Origin1',
                DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
                OriginAccessControlId: 'E1A2B3C4D5E6F7'
              },
              {
                Id: 'S3Origin2',
                DomainName: 'my-bucket.s3-website.us-east-1.amazonaws.com',
                OriginAccessControlId: 'E1A2B3C4D5E6F7'
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

    it('should not return a finding if a CloudFront distribution has an S3 origin with alternative security', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'S3Origin',
                DomainName: 'my-bucket.s3.amazonaws.com'
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      const allResources: CloudFormationResource[] = [
        resource,
        {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-bucket'
          },
          LogicalId: 'MyBucket'
        },
        {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'my-bucket',
            PolicyDocument: {
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    Service: 'cloudfront.amazonaws.com'
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*'
                }
              ]
            }
          },
          LogicalId: 'MyBucketPolicy'
        }
      ];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should not return a finding if a CloudFront distribution has an S3 origin with alternative security using condition', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'S3Origin',
                DomainName: 'my-bucket.s3.amazonaws.com'
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      const allResources: CloudFormationResource[] = [
        resource,
        {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-bucket'
          },
          LogicalId: 'MyBucket'
        },
        {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'my-bucket',
            PolicyDocument: {
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: '*',
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*',
                  Condition: {
                    StringEquals: {
                      'AWS:SourceArn': 'arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE'
                    }
                  }
                }
              ]
            }
          },
          LogicalId: 'MyBucketPolicy'
        }
      ];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).toBeNull();
    });

    it('should handle complex domain name references', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [
              {
                Id: 'S3Origin',
                DomainName: {
                  'Fn::Join': [
                    '',
                    [
                      'my-bucket',
                      '.s3.amazonaws.com'
                    ]
                  ]
                },
                OriginAccessControlId: 'E1A2B3C4D5E6F7'
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

    it('should return a finding if a CloudFront distribution has an S3 origin with bucket policy but no CloudFront access', () => {
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
                S3OriginConfig: {}
              }
            ]
          }
        },
        LogicalId: 'TestDistribution'
      };

      const allResources: CloudFormationResource[] = [
        resource,
        {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'my-bucket'
          },
          LogicalId: 'MyBucket'
        },
        {
          Type: 'AWS::S3::BucketPolicy',
          Properties: {
            Bucket: 'my-bucket',
            PolicyDocument: {
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: {
                    AWS: 'arn:aws:iam::123456789012:role/MyRole'
                  },
                  Action: 's3:GetObject',
                  Resource: 'arn:aws:s3:::my-bucket/*'
                }
              ]
            }
          },
          LogicalId: 'MyBucketPolicy'
        }
      ];

      // Act
      const result = rule.evaluate(resource, stackName, allResources);

      // Assert
      expect(result).not.toBeNull();
      expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
      expect(result?.resourceName).toBe('TestDistribution');
      expect(result?.issue).toContain('CloudFront S3 origin lacks Origin Access Control');
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
