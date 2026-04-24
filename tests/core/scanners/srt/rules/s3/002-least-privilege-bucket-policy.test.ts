import { describe, it, expect } from 'vitest';
import { S3002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/002-least-privilege-bucket-policy.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('S3002Rule', () => {
  const rule = new S3002Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::S3::BucketPolicy', () => {
      expect(rule.appliesTo('AWS::S3::BucketPolicy')).toBe(true);
    });

    it('should not apply to AWS::S3::Bucket', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
    });

    it('should not apply to other resource types', () => {
      expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    describe('S3 Bucket Policy', () => {
      it('should return finding for bucket policy with wildcard principal', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: '*',
                    Action: 's3:GetObject',
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::S3::BucketPolicy');
        expect(result?.resourceName).toBe('TestBucketPolicy');
        expect(result?.fix).toContain(`Add Condition block 'StringEquals': {'aws:SourceAccount': !Ref 'AWS::AccountId'}`);
      });

      it('should return finding for bucket policy with wildcard AWS principal', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { AWS: '*' },
                    Action: 's3:GetObject',
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.fix).toContain('Add Condition block');
      });

      it('should not return finding for bucket policy with wildcard actions but specific principal', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:role/MyRole' },
                    Action: '*',
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket policy with s3:* actions and specific principal', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:role/MyRole' },
                    Action: 's3:*',
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should return finding for bucket policy with wildcard actions and wildcard principal', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: '*',
                    Action: '*',
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.fix).toContain('Replace wildcard actions');
      });

      it('should not return finding for bucket policy with wildcard principal but condition', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: '*',
                    Action: 's3:GetObject',
                    Resource: 'arn:aws:s3:::my-bucket/*',
                    Condition: {
                      StringEquals: { 'aws:SourceAccount': { Ref: 'AWS::AccountId' } }
                    }
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket policy following least privilege', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:role/MyRole' },
                    Action: ['s3:GetObject', 's3:PutObject'],
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for Deny statements with wildcards', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Deny',
                    Principal: '*',
                    Action: '*',
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket policy with intrinsic function for Effect', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: { Ref: 'EffectParameter' },
                    Principal: { AWS: 'arn:aws:iam::123456789012:role/MyRole' },
                    Action: ['s3:GetObject', 's3:PutObject'],
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket policy with intrinsic function for Principal', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { Ref: 'PrincipalParameter' },
                    Action: ['s3:GetObject', 's3:PutObject'],
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket policy with intrinsic function for Action', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:role/MyRole' },
                    Action: { Ref: 'ActionParameter' },
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket policy with intrinsic function within Action array', () => {
        const template: Template = {
          Resources: {
            TestBucketPolicy: {
              Type: 'AWS::S3::BucketPolicy',
              Properties: {
                Bucket: { Ref: 'TestBucket' },
                PolicyDocument: {
                  Statement: [{
                    Effect: 'Allow',
                    Principal: { AWS: 'arn:aws:iam::123456789012:role/MyRole' },
                    Action: ['s3:GetObject', { Ref: 'ActionParameter' }],
                    Resource: 'arn:aws:s3:::my-bucket/*'
                  }]
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucketPolicy'] as Resource);
        expect(result).toBeNull();
      });
    });

    it('should return null for non-BucketPolicy resources', () => {
      const template: Template = {
        Resources: {
          TestBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: { BucketName: 'my-bucket' }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);
      expect(result).toBeNull();
    });
  });

  describe('evaluate (legacy stub)', () => {
    it('should return null', () => {
      const result = rule.evaluate({ Type: 'AWS::S3::BucketPolicy', Properties: {}, LogicalId: 'Test' }, stackName);
      expect(result).toBeNull();
    });
  });

  describe('rule properties', () => {
    it('should have correct id and priority', () => {
      expect(rule.id).toBe('S3-002');
      expect(rule.priority).toBe('HIGH');
    });
  });
});
