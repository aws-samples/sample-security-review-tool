import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 Terraform - mixed custom origins (at least one insecure)', () => {
  const factory = new Cf005TfAdapterFactory();

  function buildContext(origins: unknown[]): TfContext {
    const resource: TerraformResource = {
      type: 'aws_cloudfront_distribution',
      name: 'cdn',
      address: 'aws_cloudfront_distribution.cdn',
      values: {
        origin: origins,
      },
    } as TerraformResource;

    return {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };
  }

  it('flags when one custom origin is http-only while another is securely configured', () => {
    const ctx = buildContext([
      {
        origin_id: 'secure-origin',
        domain_name: 'secure.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
      {
        origin_id: 'insecure-origin',
        domain_name: 'insecure.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'http-only',
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
    ]);

    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.issue).toMatch(/HTTP only|plaintext/i);
  });

  it('flags when one custom origin uses match-viewer while another is securely configured', () => {
    const ctx = buildContext([
      {
        origin_id: 'secure-origin',
        domain_name: 'secure.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
      {
        origin_id: 'mixed-origin',
        domain_name: 'mixed.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'match-viewer',
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
    ]);

    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.issue).toMatch(/viewer/i);
  });

  it('flags when one custom origin permits a legacy SSL/TLS protocol while another is secure', () => {
    const ctx = buildContext([
      {
        origin_id: 'secure-origin',
        domain_name: 'secure.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
      {
        origin_id: 'legacy-tls-origin',
        domain_name: 'legacy.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            origin_ssl_protocols: ['TLSv1', 'TLSv1.2'],
          },
        ],
      },
    ]);

    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.issue).toMatch(/legacy|SSLv3|TLS 1\.0|TLS 1\.1/i);
  });

  it('flags when one custom origin is missing origin_ssl_protocols while another is secure', () => {
    const ctx = buildContext([
      {
        origin_id: 'secure-origin',
        domain_name: 'secure.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
            origin_ssl_protocols: ['TLSv1.2'],
          },
        ],
      },
      {
        origin_id: 'missing-protocols-origin',
        domain_name: 'missing.example.com',
        custom_origin_config: [
          {
            origin_protocol_policy: 'https-only',
          },
        ],
      },
    ]);

    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.issue).toMatch(/does not declare|SSL\/TLS protocol list/i);
  });
});
