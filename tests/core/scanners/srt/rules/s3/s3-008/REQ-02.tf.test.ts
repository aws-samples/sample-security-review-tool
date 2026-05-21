import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-02 (Terraform): S3 bucket with at least one enabled lifecycle rule passes', () => {
  it('returns null (pass) when an aws_s3_bucket_lifecycle_configuration with an enabled rule references the bucket', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-app-bucket',
        id: 'my-app-bucket',
      },
    } as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket_lifecycle',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket_lifecycle',
      values: {
        bucket: 'my-app-bucket',
        rule: [
          {
            id: 'expire-old-objects',
            status: 'Enabled',
            expiration: [{ days: 365 }],
          },
        ],
      },
    } as TerraformResource;

    const allResources = [bucket, lifecycle];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo(bucket.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('returns null (pass) when lifecycle configuration with multiple rules includes at least one enabled rule', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-app-bucket',
        id: 'my-app-bucket',
      },
    } as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket_lifecycle',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket_lifecycle',
      values: {
        bucket: 'my-app-bucket',
        rule: [
          {
            id: 'disabled-rule',
            status: 'Disabled',
            expiration: [{ days: 30 }],
          },
          {
            id: 'enabled-rule',
            status: 'Enabled',
            expiration: [{ days: 90 }],
          },
        ],
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources: [bucket, lifecycle],
    };

    const factory = new S3008TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
