import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-02 (Terraform): distribution with only native S3 origins (no custom origins)', () => {
  it('passes (literal form): all origins are native S3 origins with s3_origin_config and no custom_origin_config', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            domain_name: 'my-bucket.s3.us-east-1.amazonaws.com',
            s3_origin_config: [
              { origin_access_identity: '' },
            ],
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 's3-origin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    };

    const factory = new Cf005TfAdapterFactory();
    expect(factory.appliesTo(distribution.type)).toBe(true);

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes (reference form): native S3 origin where domain_name references an aws_s3_bucket resource', () => {
    const bucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'origin',
      address: 'aws_s3_bucket.origin',
      values: {
        bucket: 'my-origin-bucket',
      },
    };

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-origin',
            // Reference collapsed to address string
            domain_name: 'aws_s3_bucket.origin',
            s3_origin_config: [
              { origin_access_identity: 'origin-access-identity/cloudfront/E127EXAMPLE51Z' },
            ],
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 's3-origin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    };

    const factory = new Cf005TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [bucket, distribution],
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when there are multiple native S3 origins and no custom origins', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-a',
            domain_name: 'aws_s3_bucket.a',
            s3_origin_config: [{ origin_access_identity: '' }],
          },
          {
            origin_id: 's3-b',
            domain_name: 'bucket-b.s3.us-east-1.amazonaws.com',
            s3_origin_config: [{ origin_access_identity: '' }],
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 's3-a',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    };

    const factory = new Cf005TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
