import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-02 Terraform: S3 origin with in-template OAC reference', () => {
  it('passes when an S3 origin references an in-template aws_cloudfront_origin_access_control resource', () => {
    // After plan reader collapse:
    // - domain_name = aws_s3_bucket.my_bucket.bucket_regional_domain_name -> "aws_s3_bucket.my_bucket"
    // - origin_access_control_id = aws_cloudfront_origin_access_control.my_oac.id -> "aws_cloudfront_origin_access_control.my_oac"
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'my_bucket',
      address: 'aws_s3_bucket.my_bucket',
      values: { bucket: 'my-bucket-name' },
    };

    const oac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'my_oac',
      address: 'aws_cloudfront_origin_access_control.my_oac',
      values: {
        name: 'my-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      address: 'aws_cloudfront_distribution.my_distribution',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            domain_name: 'aws_s3_bucket.my_bucket',
            origin_access_control_id: 'aws_cloudfront_origin_access_control.my_oac',
          },
        ],
      },
    };

    const allResources = [bucket, oac, distribution];
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo(distribution.type)).toBe(true);
    const adapter = factory.bind(context);

    const result = cf006Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
