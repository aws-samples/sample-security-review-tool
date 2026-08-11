import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 Terraform - REQ-01: Bucket has no attached resource policy at all', () => {
  it('passes (returns null) when the bucket has no aws_s3_bucket_policy resource attached', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      address: 'aws_s3_bucket.my_bucket',
      values: {
        bucket: 'my-unpoliced-bucket',
      },
    } as TerraformResource;

    const allResources: TerraformResource[] = [bucket];

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo(bucket.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucket,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
