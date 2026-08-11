import { describe, it, expect } from 'vitest';
import { s3002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.control.js';
import { S3002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/s3/s3-002/s3-002.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('S3-002 REQ-15 (Terraform): principal list mixing wildcard and specific principals without condition', () => {
  it('flags an aws_s3_bucket_policy where the Allow statement Principal is a list containing "*" and specific principals with no condition', () => {
    const policyDocument = {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: [
              '*',
              'arn:aws:iam::123456789012:role/TrustedRole',
              'arn:aws:iam::123456789012:user/TrustedUser',
            ],
          },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    };

    const bucketPolicy: TerraformResource = {
      type: 'aws_s3_bucket_policy',
      name: 'mixed_principal',
      address: 'aws_s3_bucket_policy.mixed_principal',
      values: {
        bucket: 'aws_s3_bucket.my_bucket',
        policy: JSON.stringify(policyDocument),
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: bucketPolicy,
      allResources: [bucketPolicy],
    };

    const factory = new S3002TfAdapterFactory();
    expect(factory.appliesTo('aws_s3_bucket_policy')).toBe(true);
    const adapter = factory.bind(context);

    const result = s3002Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('S3-002');
    expect(result?.resourceName).toBe('aws_s3_bucket_policy.mixed_principal');
    expect(result?.resourceType).toBe('aws_s3_bucket_policy');
    expect(result?.issue).toMatch(/wildcard principal/i);
  });
});
