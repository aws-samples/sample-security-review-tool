import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (CF-006): A CloudFront distribution has only non-S3 origins that are
 * nevertheless OAC-eligible (Lambda function URL, MediaStore, MediaPackage v2)
 * and none of them has an origin access control attached.
 *
 * Expected behavior: FLAG. Per resolved decision, all OAC-eligible origin
 * types must have OAC configured.
 */
describe('CF-006 REQ-10 (TF): non-S3 OAC-eligible origins without OAC', () => {
  const factory = new Cf006TfAdapterFactory();

  function buildContext(resource: TerraformResource, allResources: TerraformResource[]): TfContext {
    return {
      projectName: 'test-project',
      resource,
      allResources,
    };
  }

  it('flags a distribution whose only origin is a Lambda function URL with no OAC (literal domain)', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'lambda-url-origin',
            domain_name: 'abcd1234.lambda-url.us-east-1.on.aws',
            custom_origin_config: [
              { origin_protocol_policy: 'https-only' },
            ],
          },
        ],
      },
    } as TerraformResource;

    const context = buildContext(distribution, [distribution]);
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });

  it('flags a distribution whose only origin is a MediaStore origin with no OAC (literal domain)', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'mediastore-origin',
            domain_name: 'abc123.data.mediastore.us-east-1.amazonaws.com',
            custom_origin_config: [
              { origin_protocol_policy: 'https-only' },
            ],
          },
        ],
      },
    } as TerraformResource;

    const context = buildContext(distribution, [distribution]);
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });

  it('flags a distribution whose only origin is a MediaPackage v2 origin with no OAC (reference form)', () => {
    // Reference-form: domain_name was wired from another resource attribute,
    // so it appears as the resource address string after plan reading.
    const mediaPackageChannel: TerraformResource = {
      type: 'aws_media_packagev2_channel',
      name: 'channel',
      address: 'aws_media_packagev2_channel.channel',
      values: {
        // Not an S3 bucket — this is a non-S3, OAC-eligible origin source.
        name: 'my-channel',
      },
    } as TerraformResource;

    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'mediapackage-origin',
            // Literal MediaPackage v2 egress domain (non-S3, OAC-eligible).
            domain_name: 'abc123.egress.mediapackagev2.us-east-1.amazonaws.com',
            custom_origin_config: [
              { origin_protocol_policy: 'https-only' },
            ],
          },
        ],
      },
    } as TerraformResource;

    const context = buildContext(distribution, [distribution, mediaPackageChannel]);
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });
});
