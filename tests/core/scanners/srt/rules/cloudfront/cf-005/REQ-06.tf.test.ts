import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (CF-005, Terraform):
 *
 * Scenario: A custom origin is configured to always connect to the origin over
 * HTTPS (origin_protocol_policy = "https-only"), but the allowed origin SSL/TLS
 * protocol list (origin_ssl_protocols) contains at least one legacy protocol
 * version (SSLv3, TLS 1.0, or TLS 1.1), even if a secure version (TLS 1.2 or
 * higher) is also present.
 *
 * Expected behavior: the rule must FLAG the resource. Per the resolved strict-
 * mode decision, the presence of any legacy protocol in the allowed list
 * permits CloudFront to negotiate it with the origin and weakens security.
 */

const PROJECT_NAME = 'test-project';

function buildResource(originSslProtocols: string[]): TerraformResource {
  return {
    type: 'aws_cloudfront_distribution',
    name: 'this',
    address: 'aws_cloudfront_distribution.this',
    values: {
      enabled: true,
      origin: [
        {
          origin_id: 'custom-origin-1',
          domain_name: 'origin.example.com',
          custom_origin_config: [
            {
              http_port: 80,
              https_port: 443,
              origin_protocol_policy: 'https-only',
              origin_ssl_protocols: originSslProtocols,
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;
}

function runRule(originSslProtocols: string[]) {
  const resource = buildResource(originSslProtocols);
  const ctx: TfContext = {
    projectName: PROJECT_NAME,
    resource,
    allResources: [resource],
  };
  const adapter = new Cf005TfAdapterFactory().bind(ctx);
  return cf005Control.run(adapter, ctx);
}

describe('CF-005 REQ-06 (Terraform): https-only custom origin with legacy SSL/TLS protocol in allowed list', () => {
  it('flags when allowed origin_ssl_protocols contains SSLv3 alongside TLSv1.2', () => {
    const result = runRule(['SSLv3', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when allowed origin_ssl_protocols contains TLSv1 (1.0) alongside TLSv1.2', () => {
    const result = runRule(['TLSv1', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when allowed origin_ssl_protocols contains TLSv1.1 alongside TLSv1.2', () => {
    const result = runRule(['TLSv1.1', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when allowed origin_ssl_protocols contains a legacy version alongside a modern policy entry', () => {
    const result = runRule(['TLSv1', 'TLSv1.1', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });
});
