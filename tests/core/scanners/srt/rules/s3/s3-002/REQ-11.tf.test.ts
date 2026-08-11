import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 Terraform - REQ-11: multiple allow statements with one wildcard principal and others named', () => {
  it('flags when a bucket policy has multiple Allow statements and at least one uses an unconstrained wildcard principal', () => {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          // Well-scoped statement naming a specific principal
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::111111111111:role/TrustedRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
        {
          // Unconstrained wildcard principal - this should cause a flag
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
        {
          // Another well-scoped statement naming a specific principal
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:role/AnotherTrustedRole' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const bucketResource: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-bucket' },
    } as TerraformResource;

    // Reference form: bucket argument points at the bucket resource's address
    const policyResource: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'site',
      address: 'aws_s3_bucket_policy.site',
      values: {
        bucket: 'aws_s3_bucket.site',
        policy: JSON.stringify(policyDocument),
      },
    } as TerraformResource;

    const factory = new S3002TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: policyResource,
      allResources: [bucketResource, policyResource],
    };

    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-002');
    expect(result!.resourceName).toBe('aws_s3_bucket_policy.site');
    expect(result!.resourceType).toBe('aws_s3_bucket_policy');
    expect(result!.issue).toMatch(/wildcard principal/i);
  });
});
