import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-03 (Terraform): custom origin uses HTTP-only protocol policy', () => {
  it('flags a distribution whose custom origin sets origin_protocol_policy = "http-only"', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'customOrigin',
            domain_name: 'example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'http-only',
                http_port: 80,
                https_port: 443,
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 'customOrigin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const factory = new Cf005TfAdapterFactory();
    expect(factory.appliesTo(distribution.type)).toBe(true);
    const adapter = factory.bind(context);

    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result?.status).toBe('Open');
  });
});
