import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-12 (TF): distribution with only non-OAC-eligible origins', () => {
  it('passes when the distribution has only a generic custom HTTP origin pointing at an arbitrary domain', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'custom-http-origin',
            domain_name: 'origin.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                https_port: 443,
              },
            ],
          },
        ],
      },
    };

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when the distribution has multiple non-OAC-eligible custom origins', () => {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'origin-a',
            domain_name: 'api.example.com',
            custom_origin_config: [
              { origin_protocol_policy: 'https-only' },
            ],
          },
          {
            origin_id: 'origin-b',
            domain_name: 'static.thirdparty.net',
            custom_origin_config: [
              { origin_protocol_policy: 'https-only' },
            ],
          },
        ],
      },
    };

    const factory = new Cf006TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
