import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-09 (Terraform): custom origin HTTPS-only with empty origin_ssl_protocols list', () => {
  it('flags a custom origin that uses https-only but provides an empty origin_ssl_protocols array', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'custom-origin-1',
            domain_name: 'origin.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                origin_ssl_protocols: [],
              },
            ],
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
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);
    const adapter = factory.bind(context);

    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.status).toBe('Open');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.site');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    // Empty SSL protocols list is treated as "missing" by the rule.
    expect(result?.fix).toContain('Explicitly declare the allowed SSL/TLS protocol list');
  });
});
