import { describe, it, expect } from 'vitest';
import { CFR004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/004-https-only.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CFR004Rule', () => {
  const rule = new CFR004Rule();
  const stackName = 'test-stack';

  describe('evaluate', () => {
    it('should return a finding if a CloudFront distribution has no ViewerProtocolPolicy in DefaultCacheBehavior', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              }
              // Missing ViewerProtocolPolicy
            },
            Enabled: true
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
      expect(result?.issue).toContain('CloudFront distribution allows insecure HTTP traffic');
    });

    it('should return a finding if a CloudFront distribution has ViewerProtocolPolicy set to allow-all', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'allow-all'
            },
            Enabled: true
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
      expect(result?.issue).toContain('CloudFront distribution allows insecure HTTP traffic');
    });

    it('should not return a finding if a CloudFront distribution has ViewerProtocolPolicy set to redirect-to-https', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'redirect-to-https'
            },
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1.2_2018'
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

    it('should not return a finding if a CloudFront distribution has ViewerProtocolPolicy set to https-only', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1.2_2018'
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

    it('should return a finding if a CloudFront distribution has CacheBehaviors with allow-all ViewerProtocolPolicy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            CacheBehaviors: [
              {
                PathPattern: '/api/*',
                TargetOriginId: 'APIOrigin',
                ForwardedValues: {
                  QueryString: true
                },
                ViewerProtocolPolicy: 'allow-all'
              }
            ],
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1.2_2018'
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
      expect(result?.issue).toContain('CloudFront distribution allows insecure HTTP traffic');
    });

    it('should not return a finding if a CloudFront distribution has CacheBehaviors with secure ViewerProtocolPolicy', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            CacheBehaviors: [
              {
                PathPattern: '/api/*',
                TargetOriginId: 'APIOrigin',
                ForwardedValues: {
                  QueryString: true
                },
                ViewerProtocolPolicy: 'redirect-to-https'
              },
              {
                PathPattern: '/admin/*',
                TargetOriginId: 'AdminOrigin',
                ForwardedValues: {
                  QueryString: true
                },
                ViewerProtocolPolicy: 'https-only'
              }
            ],
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1.2_2018'
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

    it('should not return a finding if a CloudFront distribution has no CacheBehaviors', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1.2_2018'
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

    it('should not return a finding if a CloudFront distribution has empty CacheBehaviors', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            CacheBehaviors: [],
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1.2_2018'
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

    it('should return a finding if a CloudFront distribution has an insecure TLS version', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            Enabled: true,
            ViewerCertificate: {
              MinimumProtocolVersion: 'TLSv1'
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
      expect(result?.issue).toContain('insecure TLS version');
    });

    it('should return a finding if a CloudFront distribution has no ViewerCertificate', () => {
      // Arrange
      const resource: CloudFormationResource = {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            DefaultCacheBehavior: {
              TargetOriginId: 'S3Origin',
              ForwardedValues: {
                QueryString: false
              },
              ViewerProtocolPolicy: 'https-only'
            },
            Enabled: true
            // Missing ViewerCertificate
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
      expect(result?.issue).toContain('no ViewerCertificate specified');
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
