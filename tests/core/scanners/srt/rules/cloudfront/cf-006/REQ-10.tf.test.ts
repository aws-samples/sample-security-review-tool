import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (CF-006): A CloudFront distribution has only non-S3 origins that are nevertheless
 * OAC-eligible (Lambda function URL origins, MediaStore origins, MediaPackage v2 origins) and
 * none of them has an origin access control attached. Expected behavior: flag.
 */

function buildDistribution(address: string, origins: any[]): TerraformResource {
  return {
    address,
    type: 'aws_cloudfront_distribution',
    name: address.split('.').pop() ?? address,
    provider_name: 'registry.terraform.io/hashicorp/aws',
    values: {
      enabled: true,
      origin: origins,
    },
  } as unknown as TerraformResource;
}

function buildTfContext(distribution: TerraformResource, otherResources: TerraformResource[] = []): TfContext {
  return {
    projectName: 'test-project',
    resource: distribution,
    allResources: [distribution, ...otherResources],
  };
}

function runRule(context: TfContext) {
  const factory = new Cf006TfAdapterFactory();
  const adapter = factory.bind(context);
  return cf006Control.run(adapter, context);
}

describe('CF-006 REQ-10 [TF] - Non-S3 OAC-eligible origins without OAC', () => {
  it('flags a distribution whose only origin is a Lambda function URL without OAC', () => {
    const distribution = buildDistribution('aws_cloudfront_distribution.lambda_url', [
      {
        origin_id: 'lambda-fn-url-origin',
        domain_name: 'abcdefghij.lambda-url.us-east-1.on.aws',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            http_port: 80,
            https_port: 443,
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
    ]);

    const result = runRule(buildTfContext(distribution));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.lambda_url');
  });

  it('flags a distribution whose only origin is a MediaStore origin without OAC', () => {
    const distribution = buildDistribution('aws_cloudfront_distribution.mediastore', [
      {
        origin_id: 'mediastore-origin',
        domain_name: 'examplecontainer.data.mediastore.us-east-1.amazonaws.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            http_port: 80,
            https_port: 443,
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
    ]);

    const result = runRule(buildTfContext(distribution));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.mediastore');
  });

  it('flags a distribution whose only origin is a MediaPackage v2 origin without OAC', () => {
    const distribution = buildDistribution('aws_cloudfront_distribution.mediapackagev2', [
      {
        origin_id: 'mediapackagev2-origin',
        domain_name: 'abc123.egress.mediapackagev2.us-east-1.amazonaws.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            http_port: 80,
            https_port: 443,
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
    ]);

    const result = runRule(buildTfContext(distribution));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.mediapackagev2');
  });

  it('flags a distribution that has multiple non-S3 OAC-eligible origins all missing OAC', () => {
    const distribution = buildDistribution('aws_cloudfront_distribution.mixed', [
      {
        origin_id: 'lambda-url',
        domain_name: 'aaaaaaaaaa.lambda-url.us-east-1.on.aws',
        custom_origin_config: [
          { origin_protocol_policy: 'https-only', http_port: 80, https_port: 443, origin_ssl_protocols: ['TLSv1.2'] },
        ],
      },
      {
        origin_id: 'mediastore',
        domain_name: 'examplecontainer.data.mediastore.us-east-1.amazonaws.com',
        custom_origin_config: [
          { origin_protocol_policy: 'https-only', http_port: 80, https_port: 443, origin_ssl_protocols: ['TLSv1.2'] },
        ],
      },
      {
        origin_id: 'mediapackagev2',
        domain_name: 'abc123.egress.mediapackagev2.us-east-1.amazonaws.com',
        custom_origin_config: [
          { origin_protocol_policy: 'https-only', http_port: 80, https_port: 443, origin_ssl_protocols: ['TLSv1.2'] },
        ],
      },
    ]);

    const result = runRule(buildTfContext(distribution));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
  });
});
