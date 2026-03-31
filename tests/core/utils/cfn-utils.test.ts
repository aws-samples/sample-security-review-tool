import { describe, it, expect } from 'vitest';
import { parseCfnTemplate } from '../../../src/assess/scanning/security-matrix/cfn-utils.js';
import { Template } from 'cloudform-types';

describe('parseCfnTemplate', () => {
  describe('filterRef - Resource references', () => {
    it('should resolve Ref to resource logical ID', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: 'test-bucket'
            }
          },
          MyBucketPolicy: {
            Type: 'AWS::S3::BucketPolicy',
            Properties: {
              Bucket: { Ref: 'MyBucket' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucketPolicy?.Properties?.Bucket).toBe('MyBucket');
    });
  });

  describe('filterRef - Parameter references', () => {
    it('should resolve Ref to parameter default value', () => {
      const template: Template = {
        Parameters: {
          Environment: {
            Type: 'String',
            Default: 'production'
          }
        },
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'Env', Value: { Ref: 'Environment' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('production');
    });

    it('should return DEFAULT when parameter has no default', () => {
      const template: Template = {
        Parameters: {
          Environment: {
            Type: 'String'
          }
        },
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'Env', Value: { Ref: 'Environment' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('DEFAULT');
    });
  });

  describe('filterRef - Pseudo-parameters', () => {
    it('should resolve AWS::AccountId', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'Account', Value: { Ref: 'AWS::AccountId' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('123456789012');
    });

    it('should resolve AWS::Region', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'Region', Value: { Ref: 'AWS::Region' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('us-east-1');
    });

    it('should resolve AWS::Partition', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'Partition', Value: { Ref: 'AWS::Partition' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('aws');
    });

    it('should resolve AWS::URLSuffix', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'URLSuffix', Value: { Ref: 'AWS::URLSuffix' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('amazonaws.com');
    });

    it('should resolve AWS::StackName', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'Stack', Value: { Ref: 'AWS::StackName' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toBe('test-stack');
    });

    it('should resolve AWS::StackId', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              Tags: [{ Key: 'StackId', Value: { Ref: 'AWS::StackId' } }]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.Tags[0].Value).toMatch(/^arn:aws:cloudformation:/);
    });

    it('should resolve AWS::NotificationARNs', () => {
      const template: Template = {
        Resources: {
          MyTopic: {
            Type: 'AWS::SNS::Topic',
            Properties: {
              Subscription: { Ref: 'AWS::NotificationARNs' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyTopic?.Properties?.Subscription).toEqual([]);
    });

    it('should resolve AWS::NoValue to undefined', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              LifecycleConfiguration: { Ref: 'AWS::NoValue' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.LifecycleConfiguration).toBeUndefined();
    });
  });

  describe('filterSub - Pseudo-parameters in Fn::Sub', () => {
    it('should resolve AWS::Region in Fn::Sub', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: { 'Fn::Sub': 'my-bucket-${AWS::Region}' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.BucketName).toBe('my-bucket-us-east-1');
    });

    it('should resolve AWS::AccountId in Fn::Sub', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: { 'Fn::Sub': 'my-bucket-${AWS::AccountId}' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.BucketName).toBe('my-bucket-123456789012');
    });

    it('should resolve AWS::Partition in Fn::Sub', () => {
      const template: Template = {
        Resources: {
          MyRole: {
            Type: 'AWS::IAM::Role',
            Properties: {
              ManagedPolicyArns: [
                { 'Fn::Sub': 'arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole' }
              ]
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyRole?.Properties?.ManagedPolicyArns[0]).toBe(
        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
      );
    });

    it('should resolve multiple pseudo-parameters in Fn::Sub', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: { 'Fn::Sub': 'cdk-assets-${AWS::AccountId}-${AWS::Region}' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.BucketName).toBe('cdk-assets-123456789012-us-east-1');
    });

    it('should resolve AWS::URLSuffix in Fn::Sub', () => {
      const template: Template = {
        Resources: {
          MyEndpoint: {
            Type: 'AWS::ApiGateway::DomainName',
            Properties: {
              DomainName: { 'Fn::Sub': 'api.example.${AWS::URLSuffix}' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyEndpoint?.Properties?.DomainName).toBe('api.example.amazonaws.com');
    });
  });

  describe('Complex scenarios', () => {
    it('should handle templates without Parameters section', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              BucketName: { 'Fn::Sub': 'my-bucket-${AWS::Region}' }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucket?.Properties?.BucketName).toBe('my-bucket-us-east-1');
    });

    it('should handle nested resource references', () => {
      const template: Template = {
        Resources: {
          MyBucket: {
            Type: 'AWS::S3::Bucket'
          },
          MyBucketPolicy: {
            Type: 'AWS::S3::BucketPolicy',
            Properties: {
              Bucket: { Ref: 'MyBucket' },
              PolicyDocument: {
                Statement: [{
                  Resource: { 'Fn::Sub': 'arn:aws:s3:::${MyBucket}/*' }
                }]
              }
            }
          }
        }
      };

      const result = parseCfnTemplate(template);
      expect(result.Resources?.MyBucketPolicy?.Properties?.Bucket).toBe('MyBucket');
      // Note: Fn::Sub with resource references requires additional parsing logic
    });
  });
});
