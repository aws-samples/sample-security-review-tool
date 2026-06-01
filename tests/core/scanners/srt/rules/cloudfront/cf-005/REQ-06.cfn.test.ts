import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (CF-005, CloudFormation):
 *
 * Scenario: A custom origin is configured to always connect to the origin over
 * HTTPS (OriginProtocolPolicy = https-only), but the allowed origin SSL/TLS
 * protocol list (OriginSSLProtocols) contains at least one legacy protocol
 * version (SSLv3, TLS 1.0, or TLS 1.1), even if a secure version (TLS 1.2 or
 * higher) is also present.
 *
 * Expected behavior: the rule must FLAG the resource. Per the resolved strict-
 * mode decision, the presence of any legacy protocol in the allowed list
 * permits CloudFront to negotiate it with the origin and weakens security.
 */

const STACK_NAME = 'test-stack';
const LOGICAL_ID = 'Distribution';

function buildContext(originSSLProtocols: string[]): CfnContext {
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
              OriginProtocolPolicy: 'https-only',
              OriginSSLProtocols: originSSLProtocols,
            },
          },
        ],
      },
    },
  } as unknown as NonNullable<Template['Resources']>[string];

  const template = {
    Resources: { [LOGICAL_ID]: resource },
  } as unknown as Template;

  return {
    stackName: STACK_NAME,
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function runRule(originSSLProtocols: string[]) {
  const ctx = buildContext(originSSLProtocols);
  const adapter = new Cf005CfnAdapterFactory().bind(ctx);
  return cf005Control.run(adapter, ctx);
}

describe('CF-005 REQ-06 (CloudFormation): https-only custom origin with legacy SSL/TLS protocol in allowed list', () => {
  it('flags when allowed SSL protocol list contains SSLv3 alongside TLSv1.2', () => {
    const result = runRule(['SSLv3', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when allowed SSL protocol list contains TLSv1 (1.0) alongside TLSv1.2', () => {
    const result = runRule(['TLSv1', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when allowed SSL protocol list contains TLSv1.1 alongside TLSv1.2', () => {
    const result = runRule(['TLSv1.1', 'TLSv1.2']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });

  it('flags when allowed SSL protocol list contains a legacy version alongside TLSv1.2_2021', () => {
    const result = runRule(['TLSv1.1', 'TLSv1.2_2021']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
  });
});
