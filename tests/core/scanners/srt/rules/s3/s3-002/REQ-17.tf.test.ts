import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 TF — REQ-17: Allow statement grants access to an explicit canonical user identifier', () => {
  it('passes when the bucket policy allow statement lists a specific CanonicalUser principal', () => {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            CanonicalUser:
              '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be',
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDocument),
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy],
    };

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo(bucketPolicy.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a CanonicalUser principal is provided as an array of specific identifiers', () => {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            CanonicalUser: [
              '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be',
              '8a6f5c1f4f9e3a2b1d0c9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c',
            ],
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDocument),
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy],
    };

    const factory = new S3002TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
