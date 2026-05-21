import { describe, it, expect } from 'vitest';
import { S3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-03 (Terraform): Bucket has lifecycle config but every rule is explicitly disabled', () => {
  it('flags an aws_s3_bucket whose associated lifecycle configuration has only Disabled rules', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.disabled_lifecycle_bucket',
      type: 'aws_s3_bucket',
      name: 'disabled_lifecycle_bucket',
      values: {
        bucket: 'disabled-lifecycle-bucket',
        id: 'disabled-lifecycle-bucket',
      },
    } as TerraformResource;

    const lifecycleConfig: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.disabled_lifecycle',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'disabled_lifecycle',
      values: {
        bucket: 'disabled-lifecycle-bucket',
        rule: [
          {
            id: 'expire-old-objects',
            status: 'Disabled',
            expiration: [{ days: 30 }],
          },
          {
            id: 'transition-to-glacier',
            status: 'Disabled',
            transition: [{ days: 90, storage_class: 'GLACIER' }],
          },
        ],
      },
    } as TerraformResource;

    const allResources = [bucket, lifecycleConfig];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const control = new S3008Control();
    const result = control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-008');
    expect(result?.resourceName).toBe(bucket.address);
    expect(result?.resourceType).toBe('aws_s3_bucket');
    expect(result?.status).toBe('Open');
  });
});
