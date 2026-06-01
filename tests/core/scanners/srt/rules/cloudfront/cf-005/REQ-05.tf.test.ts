import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - REQ-05: HTTPS-only custom origin with secure TLS protocols', () => {
  it('passes when a custom origin uses https-only with a secure-only TLS protocol list (TLS 1.2+)', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'secure',
      address: 'aws_cloudfront_distribution.secure',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'customOrigin',
            domain_name: 'origin.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.2'],
                http_port: 80,
                https_port: 443,
              },
            ],
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const factory = new Cf005TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when a custom origin uses https-only with multiple secure TLS versions (TLS 1.2 and 1.3)', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'secure',
      address: 'aws_cloudfront_distribution.secure',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'customOrigin',
            domain_name: 'api.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.2', 'TLSv1.3'],
                http_port: 80,
                https_port: 443,
              },
            ],
          },
        ],
      },
    };

    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = new Cf005TfAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
