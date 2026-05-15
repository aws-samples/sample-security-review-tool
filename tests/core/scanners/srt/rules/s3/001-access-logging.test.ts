import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/controls/s3-001.control.js';
import { CfnS3BucketAdapterFactory } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/adapters/cfn-s3-bucket-adapter.js';
import { TfS3BucketAdapterFactory } from '../../../../../../src/assess/scanning/security-matrix/rules/s3/adapters/tf-s3-bucket-adapter.js';
import { CfnContext, TfContext } from '../../../../../../src/assess/scanning/security-matrix/controls/types.js';
import { Template } from 'cloudform-types';
import { Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { TerraformResource } from '../../../../../../src/assess/scanning/security-matrix/terraform-rule-base.js';

describe('S3001Control', () => {
  const cfnFactory = new CfnS3BucketAdapterFactory();
  const tfFactory = new TfS3BucketAdapterFactory();
  const stackName = 'test-stack';
  const projectName = 'test-project';

  describe('control metadata', () => {
    it('should have correct id and priority', () => {
      expect(s3001Control.id).toBe('S3-001');
      expect(s3001Control.priority).toBe('HIGH');
    });
  });

  describe('cfnAdapter.appliesTo', () => {
    it('should apply to AWS::S3::Bucket', () => {
      expect(cfnFactory.appliesTo('AWS::S3::Bucket')).toBe(true);
    });

    it('should not apply to AWS::S3::BucketPolicy', () => {
      expect(cfnFactory.appliesTo('AWS::S3::BucketPolicy')).toBe(false);
    });

    it('should not apply to other resource types', () => {
      expect(cfnFactory.appliesTo('AWS::Lambda::Function')).toBe(false);
    });
  });

  describe('tfAdapter.appliesTo', () => {
    it('should apply to aws_s3_bucket', () => {
      expect(tfFactory.appliesTo('aws_s3_bucket')).toBe(true);
    });

    it('should not apply to aws_s3_bucket_logging', () => {
      expect(tfFactory.appliesTo('aws_s3_bucket_logging')).toBe(false);
    });
  });

  describe('CloudFormation evaluation', () => {
    function evaluateCfn(template: Template, targetResource: string) {
      const resource = template.Resources![targetResource] as Resource;
      const context: CfnContext = { stackName, template, resource, logicalId: targetResource };
      const adapter = cfnFactory.bind(context);
      return s3001Control.run(adapter, context);
    }

    it('should return finding for bucket without logging configuration', () => {
      const template: Template = { Resources: { TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket' } } } };
      const result = evaluateCfn(template, 'TestBucket');

      expect(result).not.toBeNull();
      expect(result!.resourceType).toBe('AWS::S3::Bucket');
      expect(result!.resourceName).toBe('TestBucket');
      expect(result!.check_id).toBe('S3-001');
      expect(result!.priority).toBe('HIGH');
      expect(result!.source).toBe('security-matrix');
      expect(result!.status).toBe('Open');
      expect(result!.fix).toContain('Enable S3 access logging');
      expect(result!.fix).toContain('Add a LoggingConfiguration');
    });

    it('should return finding for bucket with logging configuration without destination bucket', () => {
      const template: Template = { Resources: { TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket', LoggingConfiguration: { LogFilePrefix: 'logs/' } } } } };
      const result = evaluateCfn(template, 'TestBucket');

      expect(result).not.toBeNull();
      expect(result!.fix).toContain('Enable S3 access logging');
    });

    it('should return finding for bucket that logs to itself', () => {
      const template: Template = { Resources: { TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket', LoggingConfiguration: { DestinationBucketName: 'my-bucket', LogFilePrefix: 'logs/' } } } } };
      const result = evaluateCfn(template, 'TestBucket');

      expect(result).not.toBeNull();
      expect(result!.fix).toContain('Redirect access logs');
      expect(result!.fix).toContain('separate dedicated logging bucket');
    });

    it('should return finding for bucket that logs to itself via Ref', () => {
      const template: Template = { Resources: { TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket', LoggingConfiguration: { DestinationBucketName: { Ref: 'TestBucket' }, LogFilePrefix: 'logs/' } } } } };
      const result = evaluateCfn(template, 'TestBucket');

      expect(result).not.toBeNull();
      expect(result!.fix).toContain('Redirect access logs');
    });

    it('should not return finding for bucket with proper logging configuration', () => {
      const template: Template = {
        Resources: {
          LogBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'log-bucket' } },
          TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket', LoggingConfiguration: { DestinationBucketName: 'log-bucket', LogFilePrefix: 'logs/' } } },
        },
      };
      expect(evaluateCfn(template, 'TestBucket')).toBeNull();
    });

    it('should not return finding for bucket with CloudFormation Ref for DestinationBucketName', () => {
      const template: Template = {
        Resources: {
          LogBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'log-bucket' } },
          TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket', LoggingConfiguration: { DestinationBucketName: { Ref: 'LogBucket' }, LogFilePrefix: 'logs/' } } },
        },
      };
      expect(evaluateCfn(template, 'TestBucket')).toBeNull();
    });

    it('should not return finding for bucket with intrinsic function for BucketName', () => {
      const template: Template = {
        Resources: {
          LogBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'log-bucket' } },
          TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: { Ref: 'BucketNameParameter' }, LoggingConfiguration: { DestinationBucketName: 'log-bucket', LogFilePrefix: 'logs/' } } },
        },
      };
      expect(evaluateCfn(template, 'TestBucket')).toBeNull();
    });

    describe('Log Destination Bucket Exclusion', () => {
      it('should not return finding for bucket used as log destination via Ref', () => {
        const template: Template = {
          Resources: {
            LogBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'log-bucket' } },
            DataBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'data-bucket', LoggingConfiguration: { DestinationBucketName: { Ref: 'LogBucket' } } } },
          },
        };
        expect(evaluateCfn(template, 'LogBucket')).toBeNull();
      });

      it('should not return finding for bucket used as log destination via Fn::GetAtt', () => {
        const template: Template = {
          Resources: {
            LogBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'log-bucket' } },
            DataBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'data-bucket', LoggingConfiguration: { DestinationBucketName: { 'Fn::GetAtt': ['LogBucket', 'Arn'] } } } },
          },
        };
        expect(evaluateCfn(template, 'LogBucket')).toBeNull();
      });

      it('should not return finding for central logging bucket referenced by multiple buckets', () => {
        const template: Template = {
          Resources: {
            LoggingBucket1E5A6F3B: { Type: 'AWS::S3::Bucket', Properties: { BucketEncryption: { ServerSideEncryptionConfiguration: [{ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] } } },
            NotebookBucketF2F218E5: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'notebook-bucket', LoggingConfiguration: { DestinationBucketName: { Ref: 'LoggingBucket1E5A6F3B' }, LogFilePrefix: 'notebook-bucket-logs/' } } },
            VpcFlowLogsBucket3B29CF33: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'vpc-flow-logs-bucket', LoggingConfiguration: { DestinationBucketName: { Ref: 'LoggingBucket1E5A6F3B' }, LogFilePrefix: 'vpc-flow-logs-bucket-access/' } } },
          },
        };
        expect(evaluateCfn(template, 'LoggingBucket1E5A6F3B')).toBeNull();
      });

      it('should not return finding for log destination bucket after cfn-utils parsing (Ref resolved to string)', () => {
        const template: Template = {
          Resources: {
            LoggingBucket1E5A6F3B: { Type: 'AWS::S3::Bucket', Properties: { BucketEncryption: { ServerSideEncryptionConfiguration: [{ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] } } },
            NotebookBucketF2F218E5: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'notebook-bucket', LoggingConfiguration: { DestinationBucketName: 'LoggingBucket1E5A6F3B', LogFilePrefix: 'notebook-bucket-logs/' } } },
          },
        };
        expect(evaluateCfn(template, 'LoggingBucket1E5A6F3B')).toBeNull();
      });
    });

    it('should return null for non-S3 resources', () => {
      expect(cfnFactory.appliesTo('AWS::Lambda::Function')).toBe(false);
    });

    it('should populate cdkPath and isCustomResource from metadata', () => {
      const template: Template = {
        Resources: {
          TestBucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-bucket' }, Metadata: { 'aws:cdk:path': 'Stack/TestBucket/Resource' } },
        },
      };
      const result = evaluateCfn(template, 'TestBucket');
      expect(result).not.toBeNull();
      expect(result!.cdkPath).toBe('Stack/TestBucket/Resource');
      expect(result!.isCustomResource).toBe(false);
    });
  });

  describe('Terraform evaluation', () => {
    function evaluateTf(resource: TerraformResource, allResources: TerraformResource[]) {
      const context: TfContext = { projectName, resource, allResources };
      const adapter = tfFactory.bind(context);
      return s3001Control.run(adapter, context);
    }

    it('should return finding for bucket without logging', () => {
      const bucket: TerraformResource = { type: 'aws_s3_bucket', name: 'test', address: 'aws_s3_bucket.test', values: { bucket: 'my-bucket' } };
      const result = evaluateTf(bucket, [bucket]);

      expect(result).not.toBeNull();
      expect(result!.source).toBe('terraform-matrix');
      expect(result!.resourceType).toBe('aws_s3_bucket');
      expect(result!.resourceName).toBe('aws_s3_bucket.test');
      expect(result!.check_id).toBe('S3-001');
      expect(result!.fix).toContain('Enable S3 access logging');
      expect(result!.fix).toContain('aws_s3_bucket_logging');
    });

    it('should return finding for self-logging bucket', () => {
      const bucket: TerraformResource = { type: 'aws_s3_bucket', name: 'test', address: 'aws_s3_bucket.test', values: { bucket: 'my-bucket', logging: [{ target_bucket: 'my-bucket' }] } };
      const result = evaluateTf(bucket, [bucket]);

      expect(result).not.toBeNull();
      expect(result!.fix).toContain('Redirect access logs');
      expect(result!.fix).toContain('separate dedicated logging bucket');
    });

    it('should not return finding for bucket with separate logging resource', () => {
      const bucket: TerraformResource = { type: 'aws_s3_bucket', name: 'test', address: 'aws_s3_bucket.test', values: { bucket: 'my-bucket' } };
      const logging: TerraformResource = { type: 'aws_s3_bucket_logging', name: 'test_logging', address: 'aws_s3_bucket_logging.test_logging', values: { bucket: 'my-bucket', target_bucket: 'log-bucket' } };
      expect(evaluateTf(bucket, [bucket, logging])).toBeNull();
    });

    it('should not return finding for log destination bucket', () => {
      const logBucket: TerraformResource = { type: 'aws_s3_bucket', name: 'log', address: 'aws_s3_bucket.log', values: { bucket: 'log-bucket' } };
      const logging: TerraformResource = { type: 'aws_s3_bucket_logging', name: 'test_logging', address: 'aws_s3_bucket_logging.test_logging', values: { bucket: 'my-bucket', target_bucket: 'log-bucket' } };
      expect(evaluateTf(logBucket, [logBucket, logging])).toBeNull();
    });
  });
});
