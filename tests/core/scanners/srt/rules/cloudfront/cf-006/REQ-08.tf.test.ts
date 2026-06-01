import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-08 Terraform: multiple origins, S3 origins have OAC, non-S3 origins are out of scope', () => {
  it('passes when every S3 origin has a resolved OAC and other origins are custom HTTP origins', () => {
    const assetsBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'assets',
      address: 'aws_s3_bucket.assets',
      values: { bucket: 'my-assets-bucket' },
    } as TerraformResource;

    const mediaBucket: TerraformResource = {
      type: 'aws_s3_bucket',
      name: 'media',
      address: 'aws_s3_bucket.media',
      values: { bucket: 'my-media-bucket' },
    } as TerraformResource;

    const assetsOac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'assets',
      address: 'aws_cloudfront_origin_access_control.assets',
      values: {
        name: 'assets-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
      },
    } as TerraformResource;

    const mediaOac: TerraformResource = {
      type: 'aws_cloudfront_origin_access_control',
      name: 'media',
      address: 'aws_cloudfront_origin_access_control.media',
      values: {
        name: 'media-oac',
        origin_access_control_origin_type: 's3',
        signing_behavior: 'always',
        signing_protocol: 'sigv4',
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
            // Reference form: domain_name = aws_s3_bucket.assets.bucket_regional_domain_name
            origin_id: 'assets-origin',
            domain_name: 'aws_s3_bucket.assets',
            // Reference form: origin_access_control_id = aws_cloudfront_origin_access_control.assets.id
            origin_access_control_id: 'aws_cloudfront_origin_access_control.assets',
            s3_origin_config: [],
          },
          {
            // Literal S3 regional domain
            origin_id: 'media-origin',
            domain_name: 'my-media-bucket.s3.us-east-1.amazonaws.com',
            // Literal OAC id matched against OAC resource's `name`
            origin_access_control_id: 'media-oac',
            s3_origin_config: [],
          },
          {
            // Custom HTTP origin — not S3, not OAC-eligible
            origin_id: 'api-origin',
            domain_name: 'api.example.com',
            custom_origin_config: [
              {
                http_port: 80,
                https_port: 443,
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
          {
            // Another custom HTTP origin
            origin_id: 'legacy-origin',
            domain_name: 'legacy.example.com',
            custom_origin_config: [
              {
                http_port: 80,
                https_port: 443,
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
      },
    } as TerraformResource;

    const allResources = [assetsBucket, mediaBucket, assetsOac, mediaOac, distribution];

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources,
    };

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
    expect(adapter.findS3OriginsWithoutAccessControl()).toEqual([]);
  });
});
