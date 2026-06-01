import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(sslProtocols: unknown): TfContext {
  const resource: TerraformResource = {
    type: 'aws_cloudfront_distribution',
    name: 'legacy_custom_origin',
    address: 'aws_cloudfront_distribution.legacy_custom_origin',
    values: {
      enabled: true,
      origin: [
        {
          origin_id: 'custom-origin-1',
          domain_name: 'origin.example.com',
          custom_origin_config: [
            {
              // HTTPS enforced for connecting to the origin...
              origin_protocol_policy: 'https-only',
              http_port: 80,
              https_port: 443,
              // ...but only legacy SSL/TLS protocols are allowed.
              origin_ssl_protocols: sslProtocols,
            },
          ],
        },
      ],
    },
  } as unknown as TerraformResource;

  return {
    projectName: 'test-project',
    resource,
    allResources: [resource],
  };
}

describe('CF-005 Terraform REQ-07: legacy-only origin_ssl_protocols flags', () => {
  const factory = new Cf005TfAdapterFactory();

  it('flags when origin_ssl_protocols contains only SSLv3, TLSv1, and TLSv1.1', () => {
    const ctx = buildContext(['SSLv3', 'TLSv1', 'TLSv1.1']);
    const adapter = factory.bind(ctx);

    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.status).toBe('Open');
    expect(result?.resourceType).toBe('aws_cloudfront_distribution');
    expect(result?.resourceName).toBe('aws_cloudfront_distribution.legacy_custom_origin');
    expect(result?.issue).toMatch(/legacy SSL\/TLS protocol versions/i);
  });

  it('flags when origin_ssl_protocols contains only TLSv1.1', () => {
    const ctx = buildContext(['TLSv1.1']);
    const adapter = factory.bind(ctx);

    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when origin_ssl_protocols contains only TLSv1', () => {
    const ctx = buildContext(['TLSv1']);
    const adapter = factory.bind(ctx);

    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });
});
