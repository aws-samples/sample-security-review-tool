import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-08 (TF): empty aws_s3_bucket_logging block should be flagged', () => {
  it('flags a bucket whose associated aws_s3_bucket_logging has no target_bucket (reference form)', () => {
    // The bucket is referenced by an aws_s3_bucket_logging resource (so the
    // user clearly *intended* logging), but the logging block omits the
    // destination (target_bucket). Per the requirement, an empty/incomplete
    // logging configuration does not actually enable log delivery and the
    // bucket must be flagged.
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'site',
      address: 'aws_s3_bucket_logging.site',
      // Reference form: bucket = aws_s3_bucket.site.id collapses to the address.
      // target_bucket is absent — empty/incomplete logging configuration.
      values: { bucket: 'aws_s3_bucket.site' },
    };

    const allResources = [bucket, logging];
    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3001TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);
    expect(factory.appliesTo('aws_s3_bucket_logging')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
    expect(result?.resourceName).toBe('aws_s3_bucket.site');
    expect(result?.resourceType).toBe('aws_s3_bucket');
    expect(result?.status).toBe('Open');
  });

  it('flags a bucket whose associated aws_s3_bucket_logging has no target_bucket (literal form)', () => {
    // Literal form: user wrote the bucket name as a string in HCL.
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const logging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'site',
      address: 'aws_s3_bucket_logging.site',
      // Literal form: bucket = "my-site-bucket". No target_bucket — empty config.
      values: { bucket: 'my-site-bucket' },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources: [bucket, logging],
    };

    const adapter = new S3001TfAdapterFactory().bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
  });
});
