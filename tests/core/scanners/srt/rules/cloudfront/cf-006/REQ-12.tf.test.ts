import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 Terraform - generic custom HTTP origin (not OAC-eligible)', () => {
  it('passes when distribution only has a generic custom HTTP origin not eligible for OAC', () => {
    const distribution: TerraformResource = {
      address: 'aws_cloudfront_distribution.this',
      type: 'aws_cloudfront_distribution',
      name: 'this',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      schema_version: 0,
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'custom-http-origin',
            domain_name: 'origin.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: 'https-only',
                http_port: 80,
                https_port: 443,
                origin_ssl_protocols: ['TLSv1.2'],
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

    const factory = new Cf006TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
    expect(adapter.unprotectedS3Origins).toEqual([]);
    expect(adapter.unprotectedOacEligibleOrigins).toEqual([]);
  });
});
