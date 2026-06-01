import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - REQ-14: multiple custom origins all HTTPS-only with secure TLS', () => {
  it('passes when every custom origin uses https-only and only TLSv1.2/TLSv1.3 are allowed', () => {
    const resource: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'customOriginA',
            domain_name: 'a.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
          {
            origin_id: 'customOriginB',
            domain_name: 'b.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.2', 'TLSv1.3'],
              },
            ],
          },
          {
            origin_id: 'customOriginC',
            domain_name: 'c.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: ['TLSv1.3'],
              },
            ],
          },
        ],
      },
    } as never;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = new Cf005TfAdapterFactory().bind(context);
    const result = cf005Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
