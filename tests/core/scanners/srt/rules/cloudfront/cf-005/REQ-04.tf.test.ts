import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * CF-005 REQ-04 (Terraform)
 *
 * Scenario: A custom origin uses origin_protocol_policy = "match-viewer",
 * meaning CloudFront mirrors the viewer's protocol when connecting to the
 * origin (HTTP for HTTP viewers, HTTPS for HTTPS viewers).
 *
 * Expected behavior: flag — match-viewer is flagged unconditionally because
 * origin-level configuration alone must guarantee HTTPS to the origin.
 */
describe('CF-005 REQ-04 (TF): custom origin with match-viewer protocol policy', () => {
  const factory = new Cf005TfAdapterFactory();

  function buildContext(originProtocolPolicy: string): TfContext {
    const distribution: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'this',
      address: 'aws_cloudfront_distribution.this',
      values: {
        enabled: true,
        origin: [
          {
            origin_id: 'custom-origin',
            domain_name: 'origin.example.com',
            custom_origin_config: [
              {
                origin_protocol_policy: originProtocolPolicy,
                http_port: 80,
                https_port: 443,
                origin_ssl_protocols: ['TLSv1.2'],
              },
            ],
          },
        ],
        default_cache_behavior: [
          {
            target_origin_id: 'custom-origin',
            viewer_protocol_policy: 'redirect-to-https',
          },
        ],
      },
    } as unknown as TerraformResource;

    return {
      projectName: 'test-project',
      resource: distribution,
      allResources: [distribution],
    };
  }

  it('flags a custom origin configured with match-viewer protocol policy', () => {
    const context = buildContext('match-viewer');
    const adapter = factory.bind(context);

    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.this');
  });
});
