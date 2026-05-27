import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 Terraform - REQ-03: Default cache behavior requires HTTPS only (pass)', () => {
  it('returns no finding when viewer_protocol_policy is set to https-only', () => {
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
    expect(factory.appliesTo('aws_cloudfront_distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
