import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 / REQ-14 (Terraform): S3 origin with OAC having generic/wildcard signing config', () => {
  it('passes (reference form) — rule checks OAC reference resolution, not OAC internal config granularity', () => {
    const siteBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as TerraformResource;

    // OAC with generic/wildcard-ish internal config — still a valid resolvable OAC.
    const genericOac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'generic',
      address: 'aws_cloudfront_origin_access_control.generic',
      values: {
        name: 'generic-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'no-override',
        signing_protocol: 'sigv4',
        id: 'OACGENERICID123',
      },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-site-origin',
            // Reference form: domain_name was `aws_s3_bucket.site.bucket_regional_domain_name`,
            // collapsed to the bucket address.
            domain_name: 'aws_s3_bucket.site',
            // Reference form: origin_access_control_id was `aws_cloudfront_origin_access_control.generic.id`,
            // collapsed to the OAC address.
            origin_access_control_id: 'aws_cloudfront_origin_access_control.generic',
            s3_origin_config: [],
          },
        ],
      },
    } as TerraformResource;

    const allResources = [siteBucket, genericOac, distribution];

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo(distribution.type)).toBe(true);

    const ctx: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(ctx);

    expect(adapter.findS3OriginsWithoutAccessControl()).toEqual([]);
    expect(cf006Control.run(adapter, ctx)).toBeNull();
  });

  it('passes (literal form) — OAC referenced by literal id resolves regardless of generic config', () => {
    const siteBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'site',
      address: 'aws_s3_bucket.site',
      values: { bucket: 'my-site-bucket' },
    } as TerraformResource;

    const genericOac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'generic',
      address: 'aws_cloudfront_origin_access_control.generic',
      values: {
        name: 'generic-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'no-override',
        signing_protocol: 'sigv4',
        id: 'OACGENERICID123',
      },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 's3-site-origin',
            // Literal S3 regional domain — recognized as an S3 origin by pattern.
            domain_name: 'my-site-bucket.s3.us-east-1.amazonaws.com',
            // Literal OAC id matching the OAC resource's `id` attribute.
            origin_access_control_id: 'OACGENERICID123',
            s3_origin_config: [],
          },
        ],
      },
    } as TerraformResource;

    const allResources = [siteBucket, genericOac, distribution];

    const factory = new Cf006TfAdapterFactory();
    const ctx: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const adapter = factory.bind(ctx);

    expect(adapter.findS3OriginsWithoutAccessControl()).toEqual([]);
    expect(cf006Control.run(adapter, ctx)).toBeNull();
  });
});
