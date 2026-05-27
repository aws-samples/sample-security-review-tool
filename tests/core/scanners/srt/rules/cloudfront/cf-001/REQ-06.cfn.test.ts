import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (CloudFormation): CF-001
 *
 * Scenario: CloudFront distribution is disabled (Enabled: false) but the viewer
 * TLS configuration still permits TLS versions below 1.2 or is missing.
 *
 * Expected behavior: flag.
 *
 * Rationale: configuration is evaluated regardless of distribution enabled state,
 * due to drift and future re-enable risk.
 */

function buildContext(distributionConfig: Record<string, unknown>): CfnContext {
  const template: Template = {
    Resources: {
      MyDistribution: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: distributionConfig,
        },
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources!.MyDistribution,
    logicalId: 'MyDistribution',
  };
}

describe('CF-001 REQ-06 (CloudFormation): disabled distribution with insecure/missing TLS config is still flagged', () => {
  it('flags a disabled distribution that is missing the ViewerCertificate block entirely', () => {
    const context = buildContext({
      Enabled: false,
      DefaultCacheBehavior: {
        TargetOriginId: 'origin1',
        ViewerProtocolPolicy: 'redirect-to-https',
      },
      // No ViewerCertificate at all
    });

    const adapter = new Cf001CfnAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
    expect(result!.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result!.resourceName).toBe('MyDistribution');
    expect(result!.status).toBe('Open');
  });

  it('flags a disabled distribution whose ViewerCertificate has no MinimumProtocolVersion', () => {
    const context = buildContext({
      Enabled: false,
      ViewerCertificate: {
        AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
        SslSupportMethod: 'sni-only',
        // No MinimumProtocolVersion
      },
    });

    const adapter = new Cf001CfnAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
  });

  it('flags a disabled distribution whose ViewerCertificate uses an insecure MinimumProtocolVersion (TLSv1)', () => {
    const context = buildContext({
      Enabled: false,
      ViewerCertificate: {
        AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
        SslSupportMethod: 'sni-only',
        MinimumProtocolVersion: 'TLSv1',
      },
    });

    const adapter = new Cf001CfnAdapterFactory().bind(context);
    const result = cf001Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-001');
  });
});
