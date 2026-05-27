import { describe, it, expect } from 'vitest';
import { cf001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.control.js';
import { Cf001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-001/cf-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-001 CloudFormation - REQ-07: unknown minimum protocol version is flagged', () => {
  it('flags a CloudFront distribution whose MinimumProtocolVersion is an unrecognized/future security policy string', () => {
    const template = {
      Resources: {
        UnknownPolicyDistribution: {
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
              ViewerCertificate: {
                AcmCertificateArn: 'arn:aws:acm:us-east-1:123456789012:certificate/abc',
                SslSupportMethod: 'sni-only',
                MinimumProtocolVersion: 'TLSv9.9_2099',
              },
            },
          },
        },
      },
    } as unknown as Template;

    const logicalId = 'UnknownPolicyDistribution';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Cf001CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = (cf001Control as unknown as {
      run(a: ReturnType<typeof factory.bind>, c: CfnContext): unknown;
    }).run(adapter, context);

    expect(result).not.toBeNull();
    expect(result).toMatchObject({
      check_id: 'CF-001',
      resourceType: 'AWS::CloudFront::Distribution',
      resourceName: 'UnknownPolicyDistribution',
      status: 'Open',
    });
  });
});
