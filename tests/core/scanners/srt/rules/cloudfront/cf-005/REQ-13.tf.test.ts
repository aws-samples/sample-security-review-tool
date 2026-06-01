import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - REQ-13: unresolvable SSL/TLS protocols list contents', () => {
  it('passes when the custom origin uses HTTPS but origin_ssl_protocols contents are unknown at plan time', () => {
    // The user wired origin_ssl_protocols to an input variable / data source
    // value that is unknown at plan time. terraform show -json reports it as
    // null (omitted from planned_values' resolved literals).
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'site',
      address: 'aws_cloudfront_distribution.site',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'custom-origin',
            domain_name: 'origin.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                // Contents cannot be determined at analysis time - the list
                // itself comes from an unresolvable input (e.g., variable
                // sourced from a remote data source).
                origin_ssl_protocols: null,
              },
            ],
          },
        ],
      },
    } as unknown as TerraformResource;

    const ctx: TfContext = {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };

    const factory = new Cf005TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);
    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).toBeNull();
  });
});
