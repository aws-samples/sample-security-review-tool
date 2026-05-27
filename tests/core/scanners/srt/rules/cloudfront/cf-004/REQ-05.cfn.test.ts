import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (CFN): CF-004
 * Scenario: Default cache behavior enforces HTTPS but at least one additional
 * cache behavior allows both HTTP and HTTPS.
 * Expected Behavior: flag
 *
 * Rationale: Each cache behavior controls protocol enforcement for its matched
 * path pattern. A non-compliant additional cache behavior leaves a subset of
 * paths reachable over HTTP.
 */
describe('CF-004 :: CloudFormation :: REQ-05 :: additional cache behavior allows HTTP', () => {
  it('flags the distribution when an additional cache behavior allows HTTP even if the default enforces HTTPS', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin-1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              CacheBehaviors: [
                {
                  PathPattern: '/legacy/*',
                  TargetOriginId: 'origin-1',
                  ViewerProtocolPolicy: 'allow-all',
                },
              ],
              Origins: [
                {
                  Id: 'origin-1',
                  DomainName: 'example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['MyDistribution'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-004');
    expect(result!.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result!.resourceName).toBe('MyDistribution');
    expect(result!.status).toBe('Open');
  });
});
