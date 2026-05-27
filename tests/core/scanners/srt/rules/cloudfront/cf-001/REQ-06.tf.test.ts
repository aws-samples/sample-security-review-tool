import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (Terraform): CF-001
 *
 * Scenario: CloudFront distribution is disabled (enabled = false) but the viewer
 * TLS configuration still permits TLS versions below 1.2 or is missing.
 *
 * Expected behavior: flag.
 *
 * Rationale: configuration is evaluated regardless of distribution enabled state,
 * due to drift and future re-enable risk.
 */

function buildContext(values: Record<string, unknown>): TfContext {
  const resource: TerraformResource = {
    address: 'aws_cloudfront_distribution.my_distribution',
    type: 'aws_cloudfront_distribution',
    name: 'my_distribution',
    mode: 'managed',
    provider_name: 'registry.terraform.io/hashicorp/aws',
    values,
  } as unknown as TerraformResource;

  return {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
}

describe('CF-001 REQ-06 (Terraform): disabled distribution with insecure/missing TLS config is still flagged', () => {
  it('flags a disabled distribution that is missing the viewer_certificate block entirely', () => {
    const context = buildContext({
      enabled: false,
      // No viewer_certificate at all
    });

    const adapter = new Cf001TfAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
    expect(result!.resourceType).toBe('aws_cloudfront_distribution');
    expect(result!.resourceName).toBe('aws_cloudfront_distribution.my_distribution');
    expect(result!.status).toBe('Open');
  });

  it('flags a disabled distribution whose viewer_certificate has no minimum_protocol_version', () => {
    const context = buildContext({
      enabled: false,
      viewer_certificate: [
        {
          acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
          ssl_support_method: 'sni-only',
          // No minimum_protocol_version
        },
      ],
    });

    const adapter = new Cf001TfAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
  });

  it('flags a disabled distribution whose viewer_certificate uses an insecure minimum_protocol_version (TLSv1)', () => {
    const context = buildContext({
      enabled: false,
      viewer_certificate: [
        {
          acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
          ssl_support_method: 'sni-only',
          minimum_protocol_version: 'TLSv1',
        },
      ],
    });

    const adapter = new Cf001TfAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
  });
});
