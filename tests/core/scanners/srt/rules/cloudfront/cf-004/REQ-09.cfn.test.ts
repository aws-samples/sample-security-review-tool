import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 REQ-09 (CloudFormation): unresolvable additional cache behavior viewer protocol policy with compliant default and other behaviors', () => {
  it('passes (no finding) when an additional cache behaviors viewer protocol policy is unresolvable while default and other behaviors are compliant', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              CacheBehaviors: [
                {
                  PathPattern: '/api/*',
                  TargetOriginId: 'origin1',
                  ViewerProtocolPolicy: 'https-only',
                },
                {
                  PathPattern: '/conditional/*',
                  TargetOriginId: 'origin1',
                  // Unresolvable at analysis time — Fn::If is not resolved by preprocessing
                  ViewerProtocolPolicy: {
                    'Fn::If': ['UseHttpsOnly', 'https-only', 'redirect-to-https'],
                  },
                },
                {
                  PathPattern: '/static/*',
                  TargetOriginId: 'origin1',
                  ViewerProtocolPolicy: 'redirect-to-https',
                },
              ],
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!['MyDistribution'],
      logicalId: 'MyDistribution',
    };

    const factory = new Cf004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
