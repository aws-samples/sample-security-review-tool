import { describe, it, expect } from 'vitest';
import { S3005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/005-cloudfront-origin-access-control.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('S3005Rule', () => {
  const rule = new S3005Rule();
  const stackName = 'test-stack';

  function createTemplate(resources: Record<string, any>): Template {
    return { Resources: resources };
  }

  describe('rule properties', () => {
    it('should have correct id and priority', () => {
      expect(rule.id).toBe('S3-005');
      expect(rule.priority).toBe('HIGH');
    });

    it('should have updated description mentioning both OAC and OAI', () => {
      expect(rule.description).toContain('OAC');
      expect(rule.description).toContain('OAI');
    });
  });

  describe('appliesTo', () => {
    it('should apply to S3 bucket resources', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(true);
    });

    it('should not apply to other resource types', () => {
      expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
      expect(rule.appliesTo('AWS::CloudFront::Distribution')).toBe(false);
    });
  });

  describe('evaluateResource - non-CloudFront buckets', () => {
    it('should return null for buckets not used as CloudFront origins', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should return null for non-S3 resources', () => {
      const template = createTemplate({
        TestFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: { Handler: 'index.handler' }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestFunction);
      expect(result).toBeNull();
    });
  });

  describe('evaluateResource - OAC configurations', () => {
    it('should pass when bucket has OAC configured on origin', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                OriginAccessControlId: { Ref: 'TestOAC' },
                S3OriginConfig: {}
              }]
            }
          }
        },
        TestOAC: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'TestOAC',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4'
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });
  });

  describe('evaluateResource - OAI configurations', () => {
    it('should pass when OAI uses Fn::Sub for OriginAccessIdentity', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                S3OriginConfig: {
                  OriginAccessIdentity: { 'Fn::Sub': 'origin-access-identity/cloudfront/${TestOAI}' }
                }
              }]
            }
          }
        },
        TestOAI: {
          Type: 'AWS::CloudFront::CloudFrontOriginAccessIdentity',
          Properties: {
            CloudFrontOriginAccessIdentityConfig: { Comment: 'OAI for TestBucket' }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should pass when OAI uses Fn::Join for OriginAccessIdentity', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                S3OriginConfig: {
                  OriginAccessIdentity: {
                    'Fn::Join': ['', ['origin-access-identity/cloudfront/', { Ref: 'TestOAI' }]]
                  }
                }
              }]
            }
          }
        },
        TestOAI: {
          Type: 'AWS::CloudFront::CloudFrontOriginAccessIdentity',
          Properties: {
            CloudFrontOriginAccessIdentityConfig: { Comment: 'OAI for TestBucket' }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should pass when OAI uses static string OriginAccessIdentity', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                S3OriginConfig: {
                  OriginAccessIdentity: 'origin-access-identity/cloudfront/E127EXAMPLE51Z'
                }
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should pass when OAI uses Ref for OriginAccessIdentity', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                S3OriginConfig: {
                  OriginAccessIdentity: { Ref: 'TestOAI' }
                }
              }]
            }
          }
        },
        TestOAI: {
          Type: 'AWS::CloudFront::CloudFrontOriginAccessIdentity',
          Properties: {
            CloudFrontOriginAccessIdentityConfig: { Comment: 'OAI for TestBucket' }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });
  });

  describe('evaluateResource - no access restriction', () => {
    it('should fail when bucket has no OAC or OAI', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                S3OriginConfig: {}
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('OAC');
    });

    it('should pass when OAC is configured without bucket policy in template', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                OriginAccessControlId: { Ref: 'TestOAC' },
                S3OriginConfig: {}
              }]
            }
          }
        },
        TestOAC: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {}
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should pass when OAI is configured without bucket policy in template', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'DomainName'] },
                S3OriginConfig: {
                  OriginAccessIdentity: 'origin-access-identity/cloudfront/E127EXAMPLE51Z'
                }
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });
  });

  describe('evaluateResource - origin detection', () => {
    it('should detect bucket referenced via Ref', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { Ref: 'TestBucket' },
                S3OriginConfig: {}
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).not.toBeNull();
    });

    it('should detect bucket referenced via Fn::Sub', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::Sub': '${TestBucket}.s3.amazonaws.com' },
                S3OriginConfig: {}
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).not.toBeNull();
    });

    it('should detect bucket referenced via Fn::Sub array format', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: { 'Fn::Sub': ['${TestBucket}.s3.amazonaws.com', {}] },
                S3OriginConfig: {}
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).not.toBeNull();
    });

    it('should detect bucket referenced via Fn::Join', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3Origin',
                DomainName: {
                  'Fn::Join': ['.', [{ Ref: 'TestBucket' }, 's3', 'amazonaws.com']]
                },
                S3OriginConfig: {}
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).not.toBeNull();
    });

    it('should not flag bucket when CloudFront uses static website endpoint string', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: { BucketName: 'test-bucket' }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3WebsiteOrigin',
                DomainName: 'test-bucket.s3-website-us-east-1.amazonaws.com',
                CustomOriginConfig: { OriginProtocolPolicy: 'http-only' }
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });

    it('should not flag bucket when CloudFront uses website endpoint via Fn::GetAtt', () => {
      const template = createTemplate({
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'test-bucket',
            WebsiteConfiguration: { IndexDocument: 'index.html' }
          }
        },
        TestDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [{
                Id: 'S3WebsiteOrigin',
                DomainName: { 'Fn::GetAtt': ['TestBucket', 'WebsiteURL'] },
                CustomOriginConfig: { OriginProtocolPolicy: 'http-only' }
              }]
            }
          }
        }
      });

      const result = rule.evaluateResource(stackName, template, template.Resources!.TestBucket);
      expect(result).toBeNull();
    });
  });

  describe('evaluate (legacy method)', () => {
    it('should return null', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: { BucketName: 'test-bucket' },
        LogicalId: 'TestBucket'
      };

      expect(rule.evaluate(resource, stackName)).toBeNull();
    });
  });
});
