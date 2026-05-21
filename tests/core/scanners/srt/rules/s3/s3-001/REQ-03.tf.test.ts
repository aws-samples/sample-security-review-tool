import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-03 (TF): self-logging bucket', () => {
  it('passes (no finding) when an aws_s3_bucket_logging targets the same bucket', () => {
    const bucket = {
      address: 'aws_s3_bucket.self_logging',
      type: 'aws_s3_bucket',
      name: 'self_logging',
      values: {
        bucket: 'self-logging-bucket',
      },
    } as unknown as TerraformResource;

    const logging = {
      address: 'aws_s3_bucket_logging.self_logging',
      type: 'aws_s3_bucket_logging',
      name: 'self_logging',
      values: {
        bucket: 'self-logging-bucket',
        target_bucket: 'self-logging-bucket',
        target_prefix: 'self-logs/',
      },
    } as unknown as TerraformResource;

    const allResources = [bucket, logging];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);
    const adapter = factory.bind(context);

    const result = s3001Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
