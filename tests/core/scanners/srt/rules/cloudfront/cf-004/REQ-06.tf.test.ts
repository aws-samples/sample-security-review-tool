import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 REQ-06 (Terraform): HTTPS enforced on default and all ordered cache behaviors via mix of https-only and redirect-to-https', () => {
  it('returns no finding (pass) when all behaviors enforce HTTPS in any combination', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
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
            path_pattern: '/static/*',
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'redirect-to-https',
          },
          {
            path_pattern: '/admin/*',
            target_origin_id: 'origin1',
            viewer_protocol_policy: 'https-only',
          },
        ],
        origin: [
          {
            origin_id: 'origin1',
            domain_name: 'example.com',
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
    expect(factory.appliesTo(resource.type)).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
