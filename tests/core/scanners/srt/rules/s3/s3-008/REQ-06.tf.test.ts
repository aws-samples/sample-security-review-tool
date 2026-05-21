import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-06 Terraform: narrowly scoped enabled lifecycle rule passes', () => {
  it('passes when bucket has an enabled lifecycle rule scoped by a prefix filter', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket-name',
        id: 'my-bucket-name',
      },
    } as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket_lifecycle',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket_lifecycle',
      values: {
        bucket: 'my-bucket-name',
        rule: [
          {
            id: 'archive-logs',
            status: 'Enabled',
            filter: [{ prefix: 'logs/' }],
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
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when bucket has an enabled lifecycle rule scoped by a tag filter', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket-name',
        id: 'my-bucket-name',
      },
    } as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket_lifecycle',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket_lifecycle',
      values: {
        bucket: 'my-bucket-name',
        rule: [
          {
            id: 'archive-tagged',
            status: 'Enabled',
            filter: [{ tag: [{ key: 'archive', value: 'true' }] }],
            expiration: [{ days: 90 }],
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
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when bucket has an enabled lifecycle rule scoped by an object-size filter', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket-name',
        id: 'my-bucket-name',
      },
    } as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_bucket_lifecycle',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_bucket_lifecycle',
      values: {
        bucket: 'my-bucket-name',
        rule: [
          {
            id: 'large-objects',
            status: 'Enabled',
            filter: [{ object_size_greater_than: 1048576 }],
            expiration: [{ days: 30 }],
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
    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
