import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 Terraform - empty statements collection', () => {
  it('passes when the bucket policy document has a Statement array that is empty', () => {
    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [],
        }),
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy],
    };

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket_policy')).toBe(true);

    const adapter = factory.bind(context);
    expect(adapter.getPolicyStatements()).toEqual([]);

    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
