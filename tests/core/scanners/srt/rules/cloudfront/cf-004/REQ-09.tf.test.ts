import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 REQ-09 (Terraform): unresolvable additional cache behavior viewer protocol policy with compliant default and other behaviors', () => {
  it('passes (no finding) when an ordered cache behaviors viewer protocol policy is unresolvable (null/undefined) while default and other behaviors are compliant', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      schema_version: 0,
      values: {
        enabled: true,
        default_cache_behavior: [
          {
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
        ordered_cache_behavior: [
          {
            path_pattern: '/api/*',
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'https-only',
          },
          {
            path_pattern: '/conditional/*',
            target_origin_id: 'origin1',
            // Unresolvable at analysis time — value is not a string and cannot be asserted as non-compliant
            viewer_protocol_policy: null,
          },
          {
            path_pattern: '/static/*',
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Cf004TfAdapterFactory();
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
