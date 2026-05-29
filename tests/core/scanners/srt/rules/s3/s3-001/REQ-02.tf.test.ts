import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-02 (Terraform): bucket with logging configured to a separate destination bucket', () => {
  it('passes when an aws_s3_bucket_logging references the source bucket via address (reference form)', () => {
    const sourceBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'source',
      address: 'aws_s3_bucket.source',
      values: { bucket: 'my-source-bucket' },
    };

    const logsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'logs',
      address: 'aws_s3_bucket.logs',
      values: { bucket: 'my-logs-bucket' },
    };

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'source_logging',
      address: 'aws_s3_bucket_logging.source_logging',
      values: {
        bucket: 'aws_s3_bucket.source',
        target_bucket: 'aws_s3_bucket.logs',
        target_prefix: 'access-logs/',
      },
    };

    const allResources = [sourceBucket, logsBucket, logging];
    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: sourceBucket,
      allResources,
    };

    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('passes when an aws_s3_bucket_logging references the source bucket via literal name (literal form)', () => {
    const sourceBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'source',
      address: 'aws_s3_bucket.source',
      values: { bucket: 'my-source-bucket' },
    };

    const logsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'logs',
      address: 'aws_s3_bucket.logs',
      values: { bucket: 'my-logs-bucket' },
    };

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'source_logging',
      address: 'aws_s3_bucket_logging.source_logging',
      values: {
        bucket: 'my-source-bucket',
        target_bucket: 'my-logs-bucket',
        target_prefix: 'access-logs/',
      },
    };

    const allResources = [sourceBucket, logsBucket, logging];
    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: sourceBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
