import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(sslProtocols: unknown): CfnContext {
  const resource = {
    Type: 'AWS::CloudFront::Distribution',
    Properties: {
      DistributionConfig: {
        Enabled: true,
        DefaultCacheBehavior: {
          TargetOriginId: 'custom-origin-1',
          ViewerProtocolPolicy: 'redirect-to-https',
        },
        Origins: [
          {
            Id: 'custom-origin-1',
            DomainName: 'origin.example.com',
            CustomOriginConfig: {
              // HTTPS is enforced for connecting to the origin...
              OriginProtocolPolicy: 'https-only',
              // ...but only legacy SSL/TLS protocols are allowed.
              OriginSSLProtocols: sslProtocols,
            },
          },
        ],
      },
    },
  } as unknown as NonNullable<Template['Resources']>[string];

  const template = {
    Resources: {
      LegacyCustomOriginDistribution: resource,
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'LegacyCustomOriginDistribution',
  };
}

describe('CF-005 CloudFormation REQ-07: legacy-only OriginSSLProtocols flags', () => {
  const factory = new Cf005CfnAdapterFactory();

  it('flags when OriginSSLProtocols contains only SSLv3, TLSv1, and TLSv1.1', () => {
    const ctx = buildContext(['SSLv3', 'TLSv1', 'TLSv1.1']);
    const adapter = factory.bind(ctx);

    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.status).toBe('Open');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('LegacyCustomOriginDistribution');
    expect(result?.issue).toMatch(/legacy SSL\/TLS protocol versions/i);
  });

  it('flags when OriginSSLProtocols contains only TLSv1', () => {
    const ctx = buildContext(['TLSv1']);
    const adapter = factory.bind(ctx);

    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when OriginSSLProtocols contains only SSLv3', () => {
    const ctx = buildContext(['SSLv3']);
    const adapter = factory.bind(ctx);

    const result = cf005Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });
});
