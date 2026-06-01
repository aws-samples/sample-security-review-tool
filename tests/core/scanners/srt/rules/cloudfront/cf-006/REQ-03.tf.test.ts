import { describe, expect, it } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-03 (Terraform): S3 origin with legacy OAI but no OAC', () => {
  it('passes when an S3 bucket origin uses legacy cloudfront_access_identity_path even though origin_access_control_id is not set', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            // Reference form: domain_name = aws_s3_bucket.site.bucket_regional_domain_name
            domain_name: 'aws_s3_bucket.site',
            s3_origin_config: [
              {
                cloudfront_access_identity_path: 'origin-access-identity/cloudfront/E1ABCDEFGHIJK',
              },
            ],
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [bucket, distribution],
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
