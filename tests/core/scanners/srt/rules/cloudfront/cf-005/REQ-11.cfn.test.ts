import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import type { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 CloudFormation - mixed custom origins (at least one insecure)', () => {
  const factory = new Cf005CfnAdapterFactory();

  function buildContext(origins: unknown[]): CfnContext {
    return {
      stackName: 'test-stack',
      template: { Resources: {} } as any,
      logicalId: 'MyDistribution',
      resource: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Origins: origins,
          },
        },
      } as any,
    };
  }

  it('flags when one custom origin is HTTP-only while another is securely configured', () => {
    const ctx = buildContext([
      {
        Id: 'secure-origin',
        DomainName: 'secure.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.2'],
        },
      },
      {
        Id: 'insecure-origin',
        DomainName: 'insecure.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'http-only',
        },
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
        Id: 'secure-origin',
        DomainName: 'secure.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.2'],
        },
      },
      {
        Id: 'mixed-origin',
        DomainName: 'mixed.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'match-viewer',
          OriginSSLProtocols: ['TLSv1.2'],
        },
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
        Id: 'secure-origin',
        DomainName: 'secure.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.2'],
        },
      },
      {
        Id: 'legacy-tls-origin',
        DomainName: 'legacy.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.1', 'TLSv1.2'],
        },
      },
    ]);

    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.issue).toMatch(/legacy|SSLv3|TLS 1\.0|TLS 1\.1/i);
  });

  it('flags when one custom origin is missing OriginSSLProtocols while another is secure', () => {
    const ctx = buildContext([
      {
        Id: 'secure-origin',
        DomainName: 'secure.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.2'],
        },
      },
      {
        Id: 'missing-protocols-origin',
        DomainName: 'missing.example.com',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
        },
      },
    ]);

    const adapter = factory.bind(ctx);
    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.issue).toMatch(/does not declare|SSL\/TLS protocol list/i);
  });
});
