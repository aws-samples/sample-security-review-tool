import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 Terraform — wildcard Principal Allow with NotPrincipal exclusion of a specific identity', () => {
  it('flags a bucket policy that has Principal:"*" and a NotPrincipal excluding one identity, with no Condition', () => {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'WildcardAllowExceptOneIdentity',
          Effect: 'Allow',
          Principal: '*',
          NotPrincipal: {
            AWS: 'arn:aws:iam::123456789012:role/TrustedRole',
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
    } as TerraformResource;

    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: {
        bucket: 'my-bucket',
      },
    } as TerraformResource;

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo(bucketPolicy.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy, bucket],
    };
    const adapter = factory.bind(context);
    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('S3-002');
    expect(result!.resourceType).toBe('aws_s3_bucket_policy');
    expect(result!.resourceName).toBe('aws_s3_bucket_policy.site');
    expect(result!.status).toBe('Open');
  });
});
