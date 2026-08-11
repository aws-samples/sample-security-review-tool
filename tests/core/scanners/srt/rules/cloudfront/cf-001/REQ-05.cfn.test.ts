import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05: CloudFront distribution is configured to use the default CloudFront
 * certificate (*.cloudfront.net), regardless of any minimum protocol version
 * value set. Expected behavior: FLAG.
 *
 * AWS sets the security policy to TLSv1 "regardless of the value that you specify
 * for MinimumProtocolVersion" when CloudFrontDefaultCertificate is true, so TLS 1.0
 * and 1.1 are permitted. The declared minimum protocol version is ignored, which
 * makes a distribution declaring TLSv1.2_2021 the most important case to report:
 * the template reads as compliant and is not.
 */

const STACK_NAME = 'test-stack';
const LOGICAL_ID = 'MyDistribution';

function buildContext(viewerCertificate: Record<string, unknown>): CfnContext {
  const template: Template = {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            DefaultCacheBehavior: {
              TargetOriginId: 'origin1',
              ViewerProtocolPolicy: 'redirect-to-https',
            },
            Origins: [
              {
                Id: 'origin1',
                DomainName: 'example.com',
                CustomOriginConfig: {
                  OriginProtocolPolicy: 'https-only',
                },
              },
            ],
            ViewerCertificate: viewerCertificate,
          },
        },
      },
    },
  };

  return {
    stackName: STACK_NAME,
    template,
    resource: template.Resources![LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
}

describe('CF-001 REQ-05 (CFN): default CloudFront certificate is flagged', () => {
  const evaluate = (viewerCertificate: Record<string, unknown>) => {
    const context = buildContext(viewerCertificate);
    return cf001Control.run(new Cf001CfnAdapterFactory().bind(context), context);
  };

  it('flags when CloudFrontDefaultCertificate is true and no MinimumProtocolVersion is set', () => {
    const result = evaluate({ CloudFrontDefaultCertificate: true });

    expect(result?.check_id).toBe('CF-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });

  it('flags when CloudFrontDefaultCertificate is true and an insecure MinimumProtocolVersion is set', () => {
    const result = evaluate({ CloudFrontDefaultCertificate: true, MinimumProtocolVersion: 'TLSv1' });

    expect(result?.check_id).toBe('CF-001');
  });

  it('flags when CloudFrontDefaultCertificate is true even though a secure MinimumProtocolVersion is set', () => {
    const result = evaluate({ CloudFrontDefaultCertificate: true, MinimumProtocolVersion: 'TLSv1.2_2021' });

    expect(result?.check_id).toBe('CF-001');
  });

  it('reports the certificate as the defect rather than the protocol version', () => {
    const result = evaluate({ CloudFrontDefaultCertificate: true, MinimumProtocolVersion: 'TLSv1.2_2021' });

    expect(result?.issue).toContain('default CloudFront certificate');
  });

  it('marks the finding as requiring a manual fix', () => {
    const result = evaluate({ CloudFrontDefaultCertificate: true });

    expect(result?.manualFixRequired).toBe(true);
  });

  it('does not mark automatically fixable scenarios as manual', () => {
    const result = evaluate({
      AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
      SslSupportMethod: 'sni-only',
      MinimumProtocolVersion: 'TLSv1',
    });

    expect(result?.check_id).toBe('CF-001');
    expect(result?.manualFixRequired).toBeUndefined();
  });

  it('does not flag when CloudFrontDefaultCertificate is false and a secure policy is set', () => {
    const result = evaluate({
      CloudFrontDefaultCertificate: false,
      AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
      SslSupportMethod: 'sni-only',
      MinimumProtocolVersion: 'TLSv1.2_2021',
    });

    expect(result).toBeNull();
  });
});
