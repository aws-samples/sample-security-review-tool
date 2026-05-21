import { describe, it, expect } from 'vitest';
import { s3008Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.control.js';
import { S3008TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-008/s3-008.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-008 REQ-05 (TF): S3 bucket with lifecycle configuration but empty rules collection', () => {
  it('flags an aws_s3_bucket whose associated aws_s3_bucket_lifecycle_configuration has an empty rule list', () => {
    const bucket: TerraformResource = {
      address: 'aws_s3_bucket.my_bucket',
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      values: {
        bucket: 'my-bucket-name',
        id: 'my-bucket-name',
      },
    } as unknown as TerraformResource;

    const lifecycle: TerraformResource = {
      address: 'aws_s3_bucket_lifecycle_configuration.my_lc',
      type: 'aws_s3_bucket_lifecycle_configuration',
      name: 'my_lc',
      values: {
        bucket: 'my-bucket-name',
        rule: [],
      },
    } as unknown as TerraformResource;

    const allResources = [bucket, lifecycle];

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const factory = new S3008TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket')).toBe(true);

    const adapter = factory.bind(context);
    const result = s3008Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-008');
    expect(result?.resourceType).toBe('aws_s3_bucket');
    expect(result?.resourceName).toBe('aws_s3_bucket.my_bucket');
    expect(result?.status).toBe('Open');
  });
});
