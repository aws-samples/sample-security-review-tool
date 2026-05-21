import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-01 (Terraform): S3 bucket has no lifecycle configuration defined', () => {
  it('flags an aws_s3_bucket that has no associated aws_s3_bucket_lifecycle_configuration', () => {
    const bucket = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket-without-lifecycle',
      },
    };

    // Note: no aws_s3_bucket_lifecycle_configuration resource exists in the project.
    const allResources = [bucket];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket as any,
      allResources: allResources as any,
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo(bucket.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-008');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
    expect(result?.resourceType).toBe('aws_s3_bucket');
    expect(result?.resourceName).toBe('aws_s3_bucket.my_bucket');
  });
});
