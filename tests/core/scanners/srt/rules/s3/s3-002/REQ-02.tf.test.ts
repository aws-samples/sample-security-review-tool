import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 REQ-02 (Terraform): Bucket policy with only deny statements should pass', () => {
  it('does not flag a bucket policy (literal bucket reference) that contains only Deny statements', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      address: 'aws_s3_bucket.my_bucket',
      values: { bucket: 'my-bucket' },
    } as TerraformResource;

    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyInsecureTransport',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: [
            'arn:aws:s3:::my-bucket',
            'arn:aws:s3:::my-bucket/*',
          ],
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        },
        {
          Sid: 'DenyUnencryptedUploads',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringNotEquals: { 's3:x-amz-server-side-encryption': 'AES256' },
          },
        },
      ],
    };

    const policy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'my_policy',
      address: 'aws_s3_bucket_policy.my_policy',
      values: {
        bucket: 'my-bucket',
        policy: JSON.stringify(policyDocument),
      },
    } as TerraformResource;

    const factory = new S3002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: policy,
      allResources: [bucket, policy],
    };

    expect(factory.appliesTo('aws_s3_bucket_policy')).toBe(true);
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });

  it('does not flag a bucket policy (reference-form bucket) that contains only Deny statements', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      address: 'aws_s3_bucket.my_bucket',
      values: { bucket: 'my-bucket' },
    } as TerraformResource;

    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenySpecificPrincipal',
          Effect: 'Deny',
          Principal: { AWS: 'arn:aws:iam::999999999999:root' },
          Action: 's3:*',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    // Reference form: `bucket = aws_s3_bucket.my_bucket.id` collapses to the address string.
    const policy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'my_policy',
      address: 'aws_s3_bucket_policy.my_policy',
      values: {
        bucket: 'aws_s3_bucket.my_bucket',
        policy: JSON.stringify(policyDocument),
      },
    } as TerraformResource;

    const factory = new S3002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: policy,
      allResources: [bucket, policy],
    };

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
