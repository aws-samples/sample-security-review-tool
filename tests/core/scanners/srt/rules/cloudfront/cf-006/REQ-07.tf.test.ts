import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-07 Terraform: S3 origin with legacy OAI and dangling OAC reference', () => {
  it('passes when an S3 origin specifies both a legacy cloudfront_access_identity_path and a dangling origin_access_control_id (literal form)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'S3Origin',
            domain_name: 'my-site-bucket',
            // Dangling literal OAC id: no aws_cloudfront_origin_access_control
            // resource has an id/name matching this string.
            origin_access_control_id: 'nonexistent-oac-id',
            s3_origin_config: [
              {
                cloudfront_access_identity_path:
                  'origin-access-identity/cloudfront/E1ABCDEFGHIJKL',
              },
            ],
          },
        ],
      },
    };

    const allResources = [bucket, distribution];
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf006TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when an S3 origin specifies a legacy OAI and an origin_access_control_id pointing at an unmanaged OAC address (reference form)', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'S3Origin',
            // Reference form: domain_name collapsed to the bucket's address.
            domain_name: 'aws_s3_bucket.site',
            // Reference form for an OAC that doesn't exist in this plan.
            origin_access_control_id: 'aws_cloudfront_origin_access_control.missing',
            s3_origin_config: [
              {
                cloudfront_access_identity_path:
                  'origin-access-identity/cloudfront/E1ABCDEFGHIJKL',
              },
            ],
          },
        ],
      },
    };

    const allResources = [bucket, distribution];
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf006TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
