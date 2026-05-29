import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 Terraform - REQ-01: bucket without logging and not a log destination', () => {
  it('flags an aws_s3_bucket that has no aws_s3_bucket_logging configured and is not referenced as a target_bucket by any other bucket logging resource', () => {
    const unloggedBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'unlogged',
      address: 'aws_s3_bucket.unlogged',
      values: { bucket: 'my-unlogged-bucket' },
    };

    // Another bucket that does have logging, but does NOT target our unlogged bucket
    const otherBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'other',
      address: 'aws_s3_bucket.other',
      values: { bucket: 'some-other-bucket' },
    };

    const logsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'logs',
      address: 'aws_s3_bucket.logs',
      values: { bucket: 'my-logs-bucket' },
    };

    // Reference-form logging: target_bucket points to logsBucket (NOT unloggedBucket)
    const otherLogging: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'other',
      address: 'aws_s3_bucket_logging.other',
      values: {
        bucket: 'aws_s3_bucket.other',
        target_bucket: 'aws_s3_bucket.logs',
      },
    };

    const allResources = [unloggedBucket, otherBucket, logsBucket, otherLogging];

    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: unloggedBucket,
      allResources,
    };

    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-001');
    expect(result?.resourceName).toBe('aws_s3_bucket.unlogged');
    expect(result?.resourceType).toBe('aws_s3_bucket');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
