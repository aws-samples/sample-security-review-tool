import { describe, it, expect } from 'vitest';
import { cf002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.control.js';
import { Cf002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-002 REQ-06 CloudFormation: distribution associated with WAF web ACL via logical/symbolic reference to a same-template resource', () => {
  it('passes when WebACLId references another WAF web ACL resource in the same template (resolved to logical ID string after preprocessing)', () => {
    // Simulating post-preprocessing template state where !Ref MyWebACL has been
    // resolved to the literal logical ID string "MyWebACL".
    const template: Template = {
      Resources: {
        MyWebACL: {
          Type: 'AWS::WAFv2::WebACL',
          Properties: {
            Name: 'my-web-acl',
            Scope: 'CLOUDFRONT',
            DefaultAction: { Allow: {} },
            VisibilityConfig: {
              CloudWatchMetricsEnabled: true,
              MetricName: 'myWebAcl',
              SampledRequestsEnabled: true,
            },
          },
        },
        MyDistribution: {
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
              // After preprocessing, !Ref MyWebACL resolves to the string "MyWebACL"
              WebACLId: 'MyWebACL',
            },
          },
        },
      },
    };

    const factory = new Cf002CfnAdapterFactory();
    const logicalId = 'MyDistribution';
    const resource = template.Resources!['MyDistribution'];

    expect(factory.appliesTo(resource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const adapter = factory.bind(context);
    const result = cf002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
