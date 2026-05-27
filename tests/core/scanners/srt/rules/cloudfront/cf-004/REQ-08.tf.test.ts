import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (TF): Default cache behavior is "compliant" but its viewer_protocol_policy
 * is unresolvable at analysis time (e.g., not a string — value depends on a
 * variable/expression that the planner could not concretize). All ordered
 * (additional) cache behaviors have resolved, compliant policies.
 *
 * Expected: PASS (no finding) — per resolved decision, when the value cannot be
 * determined the rule must avoid false positives.
 */
describe('CF-004 Terraform - REQ-08: unresolvable default viewer_protocol_policy with compliant additional behaviors', () => {
  it('passes (returns null) when the default_cache_behavior viewer_protocol_policy is unresolvable and all ordered_cache_behavior values are compliant', () => {
    const resource: TerraformResource = {
      address: 'aws_cloudfront_distribution.my_distribution',
      type: 'aws_cloudfront_distribution',
      name: 'my_distribution',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        enabled: true,
        default_cache_behavior: [
          {
            target_origin_id: 'origin-1',
            // Unresolvable at analysis time — represented as a non-string
            // (e.g., null/undefined produced by an unknown plan value).
            viewer_protocol_policy: null,
          },
        ],
        ordered_cache_behavior: [
          {
            path_pattern: '/api/*',
            target_origin_id: 'origin-1',
            viewer_protocol_policy: 'redirect-to-https',
          },
          {
            path_pattern: '/static/*',
            target_origin_id: 'origin-1',
            viewer_protocol_policy: 'https-only',
          },
        ],
      },
    } as unknown as TerraformResource;

    const factory = new Cf004TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
