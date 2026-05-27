import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (Terraform): CF-004
 * Scenario: Default cache behavior enforces HTTPS but at least one additional
 * (ordered) cache behavior allows both HTTP and HTTPS.
 * Expected Behavior: flag
 *
 * Rationale: Each cache behavior controls protocol enforcement for its matched
 * path pattern. A non-compliant additional cache behavior leaves a subset of
 * paths reachable over HTTP.
 */
describe('CF-004 :: Terraform :: REQ-05 :: ordered cache behavior allows HTTP', () => {
  it('flags the distribution when an ordered_cache_behavior allows HTTP even if the default enforces HTTPS', () => {
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
            target_origin_id: 'origin-1',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
        ordered_cache_behavior: [
          {
            path_pattern: '/legacy/*',
            target_origin_id: 'origin-1',
            viewer_protocol_policy: 'allow-all',
          },
        ],
        origin: [
          {
            origin_id: 'origin-1',
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

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-004');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result!.status).toBe('Open');
  });
});
