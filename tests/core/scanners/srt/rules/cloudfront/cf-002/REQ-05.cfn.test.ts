import { describe, it, expect } from 'vitest';
import { cf002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.control.js';
import { Cf002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-002 CloudFormation - REQ-05: Unresolvable WebACLId value', () => {
  it('should pass when WebACLId is an unresolved Fn::If intrinsic (cannot be statically resolved)', () => {
    // Fn::If is NOT resolved by parseCfnTemplate preprocessing - it remains as
    // an opaque object. The rule should pass to avoid false positives, since
    // the actual association is determined only at deploy time.
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
              Origins: [
                {
                  Id: 'origin1',
                  DomainName: 'example.com',
                },
              ],
              WebACLId: {
                'Fn::If': [
                  'EnableWaf',
                  'arn:aws:wafv2:us-east-1:123456789012:global/webacl/MyAcl/abc',
                  { Ref: 'AWS::NoValue' },
                ],
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf002CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf002Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('should pass when WebACLId is an unresolved Fn::ImportValue (cross-stack reference)', () => {
    // Fn::ImportValue is NOT resolved by preprocessing. It remains as an
    // opaque object whose actual value is determined at deploy time.
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
              Origins: [
                {
                  Id: 'origin1',
                  DomainName: 'example.com',
                },
              ],
              WebACLId: {
                'Fn::ImportValue': 'shared-waf-stack:WebAclArn',
              },
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf002CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf002Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
