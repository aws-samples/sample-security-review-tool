import { describe, it, expect } from 'vitest';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * CF-005 REQ-04 (CloudFormation)
 *
 * Scenario: A custom origin uses OriginProtocolPolicy = "match-viewer", meaning
 * CloudFront mirrors the viewer's protocol when connecting to the origin
 * (HTTP for HTTP viewers, HTTPS for HTTPS viewers).
 *
 * Expected behavior: flag — match-viewer is flagged unconditionally because
 * origin-level configuration alone must guarantee HTTPS to the origin.
 */
describe('CF-005 REQ-04 (CFN): custom origin with match-viewer protocol policy', () => {
  const factory = new Cf005CfnAdapterFactory();

  function buildContext(originProtocolPolicy: string): CfnContext {
    const template: Template = {
      Resources: {
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'custom-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'custom-origin',
                  DomainName: 'origin.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: originProtocolPolicy,
                  },
                },
              ],
            },
          },
        },
      },
    };

    return {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['Distribution'],
      logicalId: 'Distribution',
    };
  }

  it('flags a custom origin configured with match-viewer protocol policy', () => {
    const context = buildContext('match-viewer');
    const adapter = factory.bind(context);

    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('Distribution');
  });
});
