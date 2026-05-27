import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (CFN): Default cache behavior is "compliant" but its viewer protocol
 * policy is unresolvable at analysis time (e.g., Fn::If). All additional cache
 * behaviors have resolved, compliant policies.
 *
 * Expected: PASS (no finding) — per resolved decision, when the value cannot be
 * determined the rule must avoid false positives.
 */
describe('CF-004 CloudFormation - REQ-08: unresolvable default viewer protocol policy with compliant additional behaviors', () => {
  it('passes (returns null) when the default cache behavior viewer protocol policy is an unresolved intrinsic and all additional behaviors are compliant', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin-1',
                // Unresolved intrinsic — value cannot be determined at analysis time
                ViewerProtocolPolicy: {
                  'Fn::If': ['UseHttpsOnly', 'https-only', 'redirect-to-https'],
                },
              },
              CacheBehaviors: [
                {
                  PathPattern: '/api/*',
                  TargetOriginId: 'origin-1',
                  ViewerProtocolPolicy: 'redirect-to-https',
                },
                {
                  PathPattern: '/static/*',
                  TargetOriginId: 'origin-1',
                  ViewerProtocolPolicy: 'https-only',
                },
              ],
            },
          },
        },
      },
    };

    const factory = new Cf004CfnAdapterFactory();
    const resource = template.Resources!['MyDistribution'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyDistribution',
    };

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
