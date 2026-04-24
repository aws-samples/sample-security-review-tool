import { describe, it, expect } from 'vitest';
import { S3001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/001-access-logging.js';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('S3001Rule', () => {
  const rule = new S3001Rule();
  const stackName = 'test-stack';

  describe('appliesTo', () => {
    it('should apply to AWS::S3::Bucket', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(true);
    });

    it('should not apply to AWS::S3::BucketPolicy', () => {
      expect(rule.appliesTo('AWS::S3::BucketPolicy')).toBe(false);
    });

    it('should not apply to other resource types', () => {
      expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    describe('S3 Bucket Logging', () => {
      it('should return finding for bucket without logging configuration', () => {
        const template: Template = {
          Resources: {
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: { BucketName: 'my-bucket' }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::S3::Bucket');
        expect(result?.resourceName).toBe('TestBucket');
        expect(result?.fix).toContain('Add LoggingConfiguration property');
      });

      it('should return finding for bucket with logging configuration without destination bucket', () => {
        const template: Template = {
          Resources: {
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'my-bucket',
                LoggingConfiguration: { LogFilePrefix: 'logs/' }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::S3::Bucket');
        expect(result?.resourceName).toBe('TestBucket');
        expect(result?.fix).toContain('Set DestinationBucketName');
      });

      it('should return finding for bucket that logs to itself', () => {
        const template: Template = {
          Resources: {
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'my-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: 'my-bucket',
                  LogFilePrefix: 'logs/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.resourceType).toBe('AWS::S3::Bucket');
        expect(result?.resourceName).toBe('TestBucket');
        expect(result?.fix).toContain('Use a dedicated logging bucket different from the source bucket');
      });

      it('should return finding for bucket that logs to itself via Ref', () => {
        const template: Template = {
          Resources: {
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'my-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: { Ref: 'TestBucket' },
                  LogFilePrefix: 'logs/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);

        expect(result).not.toBeNull();
        expect(result?.fix).toContain('Use a dedicated logging bucket');
      });

      it('should not return finding for bucket with proper logging configuration', () => {
        const template: Template = {
          Resources: {
            LogBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: { BucketName: 'log-bucket' }
            },
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'my-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: 'log-bucket',
                  LogFilePrefix: 'logs/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket with CloudFormation reference for DestinationBucketName', () => {
        const template: Template = {
          Resources: {
            LogBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: { BucketName: 'log-bucket' }
            },
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'my-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: { Ref: 'LogBucket' },
                  LogFilePrefix: 'logs/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket with intrinsic function for BucketName', () => {
        const template: Template = {
          Resources: {
            LogBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: { BucketName: 'log-bucket' }
            },
            TestBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: { Ref: 'BucketNameParameter' },
                LoggingConfiguration: {
                  DestinationBucketName: 'log-bucket',
                  LogFilePrefix: 'logs/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['TestBucket'] as Resource);
        expect(result).toBeNull();
      });
    });

    describe('Log Destination Bucket Exclusion', () => {
      it('should not return finding for bucket used as log destination via Ref', () => {
        const template: Template = {
          Resources: {
            LogBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: { BucketName: 'log-bucket' }
            },
            DataBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'data-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: { Ref: 'LogBucket' }
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['LogBucket'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for bucket used as log destination via Fn::GetAtt', () => {
        const template: Template = {
          Resources: {
            LogBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: { BucketName: 'log-bucket' }
            },
            DataBucket: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'data-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: { 'Fn::GetAtt': ['LogBucket', 'Arn'] }
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['LogBucket'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for central logging bucket referenced by multiple buckets', () => {
        const template: Template = {
          Resources: {
            LoggingBucket1E5A6F3B: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketEncryption: { ServerSideEncryptionConfiguration: [{ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] },
                PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true },
                VersioningConfiguration: { Status: 'Enabled' }
              }
            },
            NotebookBucketF2F218E5: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'notebook-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: { Ref: 'LoggingBucket1E5A6F3B' },
                  LogFilePrefix: 'notebook-bucket-logs/'
                }
              }
            },
            VpcFlowLogsBucket3B29CF33: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'vpc-flow-logs-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: { Ref: 'LoggingBucket1E5A6F3B' },
                  LogFilePrefix: 'vpc-flow-logs-bucket-access/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['LoggingBucket1E5A6F3B'] as Resource);
        expect(result).toBeNull();
      });

      it('should not return finding for log destination bucket after cfn-utils parsing (Ref resolved to string)', () => {
        const template: Template = {
          Resources: {
            LoggingBucket1E5A6F3B: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketEncryption: { ServerSideEncryptionConfiguration: [{ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] }
              }
            },
            NotebookBucketF2F218E5: {
              Type: 'AWS::S3::Bucket',
              Properties: {
                BucketName: 'notebook-bucket',
                LoggingConfiguration: {
                  DestinationBucketName: 'LoggingBucket1E5A6F3B',
                  LogFilePrefix: 'notebook-bucket-logs/'
                }
              }
            }
          }
        };

        const result = rule.evaluateResource(stackName, template, template.Resources!['LoggingBucket1E5A6F3B'] as Resource);
        expect(result).toBeNull();
      });
    });

    it('should return null for non-S3 resources', () => {
      const template: Template = {
        Resources: {
          TestFunction: {
            Type: 'AWS::Lambda::Function',
            Properties: {
              Handler: 'index.handler',
              Runtime: 'nodejs14.x',
              Code: { S3Bucket: 'my-bucket', S3Key: 'my-key' }
            }
          }
        }
      };

      const result = rule.evaluateResource(stackName, template, template.Resources!['TestFunction'] as Resource);
      expect(result).toBeNull();
    });
  });

  describe('evaluate (legacy stub)', () => {
    it('should return null', () => {
      const result = rule.evaluate({ Type: 'AWS::S3::Bucket', Properties: {}, LogicalId: 'Test' }, stackName);
      expect(result).toBeNull();
    });
  });

  describe('rule properties', () => {
    it('should have correct id and priority', () => {
      expect(rule.id).toBe('S3-001');
      expect(rule.priority).toBe('HIGH');
    });
  });
});
