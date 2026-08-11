import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05: CloudFront distribution is configured to use the default CloudFront
 * certificate (*.cloudfront.net), regardless of any minimum protocol version
 * value set. Expected behavior: FLAG.
 *
 * In Terraform, the default CloudFront certificate is indicated by setting
 * cloudfront_default_certificate = true on the viewer_certificate block.
 *
 * AWS sets the security policy to TLSv1 regardless of minimum_protocol_version in
 * this case, so TLS 1.0 and 1.1 are permitted and the declared value is ignored.
 */

const PROJECT_NAME = 'test-project';

function buildContext(viewerCertificate: Record<string, unknown>): TfContext {
  const resource: TerraformResource = {
    address: 'aws_cloudfront_distribution.test',
    type: 'aws_cloudfront_distribution',
    name: 'test',
    mode: 'managed',
    provider_name: 'registry.terraform.io/hashicorp/aws',
    schema_version: 0,
    values: {
      enabled: true,
      viewer_certificate: [viewerCertificate],
    },
  } as unknown as TerraformResource;

  return {
    projectName: PROJECT_NAME,
    resource,
    allResources: [resource],
  };
}

describe('CF-001 REQ-05 (TF): default CloudFront certificate is flagged', () => {
  const evaluate = (viewerCertificate: Record<string, unknown>) => {
    const context = buildContext(viewerCertificate);
    return cf001Control.run(new Cf001TfAdapterFactory().bind(context), context);
  };

  it('flags when cloudfront_default_certificate is true and no minimum_protocol_version is set', () => {
    const result = evaluate({ cloudfront_default_certificate: true });

    expect(result?.check_id).toBe('CF-001');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.test');
  });

  it('flags when cloudfront_default_certificate is true and an insecure minimum_protocol_version is set', () => {
    const result = evaluate({ cloudfront_default_certificate: true, minimum_protocol_version: 'TLSv1' });

    expect(result?.check_id).toBe('CF-001');
  });

  it('flags when cloudfront_default_certificate is true even though a secure minimum_protocol_version is set', () => {
    const result = evaluate({ cloudfront_default_certificate: true, minimum_protocol_version: 'TLSv1.2_2021' });

    expect(result?.check_id).toBe('CF-001');
  });

  it('reports the certificate as the defect rather than the protocol version', () => {
    const result = evaluate({ cloudfront_default_certificate: true, minimum_protocol_version: 'TLSv1.2_2021' });

    expect(result?.issue).toContain('default CloudFront certificate');
  });

  it('marks the finding as requiring a manual fix', () => {
    const result = evaluate({ cloudfront_default_certificate: true });

    expect(result?.manualFixRequired).toBe(true);
  });

  it('does not mark automatically fixable scenarios as manual', () => {
    const result = evaluate({
      acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
      ssl_support_method: 'sni-only',
      minimum_protocol_version: 'TLSv1',
    });

    expect(result?.check_id).toBe('CF-001');
    expect(result?.manualFixRequired).toBeUndefined();
  });

  it('does not flag when cloudfront_default_certificate is false and a secure policy is set', () => {
    const result = evaluate({
      cloudfront_default_certificate: false,
      acm_certificate_arn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
      ssl_support_method: 'sni-only',
      minimum_protocol_version: 'TLSv1.2_2021',
    });

    expect(result).toBeNull();
  });
});
