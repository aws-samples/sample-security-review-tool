import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-03 (TF): self-logging bucket passes', () => {
  it('passes when aws_s3_bucket_logging targets the same bucket as its source (reference form)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'self',
      address: 'aws_s3_bucket.self',
      values: { bucket: 'self-logging-bucket' },
    } as TerraformResource;

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'self',
      address: 'aws_s3_bucket_logging.self',
      values: {
        bucket: 'aws_s3_bucket.self',
        target_bucket: 'aws_s3_bucket.self',
        target_prefix: 'logs/',
      },
    } as TerraformResource;

    const allResources = [bucket, logging];
    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);
    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when aws_s3_bucket_logging targets the same bucket via literal name (literal form)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'self',
      address: 'aws_s3_bucket.self',
      values: { bucket: 'self-logging-bucket' },
    } as TerraformResource;

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'self',
      address: 'aws_s3_bucket_logging.self',
      values: {
        bucket: 'self-logging-bucket',
        target_bucket: 'self-logging-bucket',
        target_prefix: 'logs/',
      },
    } as TerraformResource;

    const allResources = [bucket, logging];
    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
