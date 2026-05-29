import { describe, it, expect } from 'vitest';
import { s3001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.control.js';
import { S3001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-001/s3-001.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-001 REQ-06 (Terraform): destination bucket whose referencer has unresolvable logging config', () => {
  it('passes (reference form) for a bucket with no logging that is referenced as target_bucket by a logging resource whose source bucket is unresolvable (null)', () => {
    // destination_bucket has no logging of its own.
    // An aws_s3_bucket_logging resource targets destination_bucket as its
    // target_bucket via a reference, but its `bucket` field — which bucket is
    // being logged FROM — is null (unresolvable: e.g. multi-source interpolation).
    // The destination exemption should still apply to destination_bucket.
    const destinationBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'destination',
      address: 'aws_s3_bucket.destination',
      values: { bucket: 'my-destination-bucket' },
    } as unknown as TerraformResource;

    const loggingWithUnresolvableSource: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app',
      address: 'aws_s3_bucket_logging.app',
      values: {
        bucket: null,
        target_bucket: 'aws_s3_bucket.destination',
      },
    } as unknown as TerraformResource;

    const allResources = [destinationBucket, loggingWithUnresolvableSource];

    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: destinationBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes (literal form) for a bucket with no logging referenced by literal name as target_bucket while the logging source bucket is unresolvable', () => {
    // Same scenario but the logging resource references the destination bucket
    // by its literal name string rather than via a resource address reference.
    const destinationBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'destination',
      address: 'aws_s3_bucket.destination',
      values: { bucket: 'my-destination-bucket' },
    } as unknown as TerraformResource;

    const loggingWithUnresolvableSource: TerraformResource = {
      type: 'aws_s3_bucket_logging',
      name: 'app',
      address: 'aws_s3_bucket_logging.app',
      values: {
        bucket: null,
        target_bucket: 'my-destination-bucket',
      },
    } as unknown as TerraformResource;

    const allResources = [destinationBucket, loggingWithUnresolvableSource];

    const factory = new S3001TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: destinationBucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
