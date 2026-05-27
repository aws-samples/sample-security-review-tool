import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05: CloudFront distribution is configured to use the default CloudFront
 * certificate (*.cloudfront.net), regardless of any minimum protocol version
 * value set. Expected behavior: the rule passes (returns null).
 *
 * Per user-resolved decision: when the SSL certificate is the default
 * CloudFront certificate, this rule passes. AWS forces TLSv1 in this case
 * but the rule defers to the default-certificate scenario as out of scope.
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

describe('CF-001 REQ-05 (CFN): default CloudFront certificate passes', () => {
  it('returns null when CloudFrontDefaultCertificate is true and no MinimumProtocolVersion is set', () => {
    const context = buildContext({
      CloudFrontDefaultCertificate: true,
    });
    const adapter = new Cf001CfnAdapterFactory().bind(context);

    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('returns null when CloudFrontDefaultCertificate is true even if an insecure MinimumProtocolVersion is set', () => {
    const context = buildContext({
      CloudFrontDefaultCertificate: true,
      MinimumProtocolVersion: 'TLSv1',
    });
    const adapter = new Cf001CfnAdapterFactory().bind(context);

    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('returns null when CloudFrontDefaultCertificate is true even if a secure MinimumProtocolVersion is set', () => {
    const context = buildContext({
      CloudFrontDefaultCertificate: true,
      MinimumProtocolVersion: 'TLSv1.2_2021',
    });
    const adapter = new Cf001CfnAdapterFactory().bind(context);

    const result = cf001Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
