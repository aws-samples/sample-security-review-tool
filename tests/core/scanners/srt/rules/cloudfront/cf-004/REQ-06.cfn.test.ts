import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 REQ-06 (CloudFormation): HTTPS enforced on default and all additional cache behaviors via mix of https-only and redirect-to-https', () => {
  it('returns no finding (pass) when all behaviors enforce HTTPS in any combination', () => {
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
                  PathPattern: '/static/*',
                  TargetOriginId: 'origin1',
                  ViewerProtocolPolicy: 'redirect-to-https',
                },
                {
                  PathPattern: '/admin/*',
                  TargetOriginId: 'origin1',
                  ViewerProtocolPolicy: 'https-only',
                },
              ],
              Origins: [
                {
                  Id: 'origin1',
                  DomainName: 'example.com',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const logicalId = 'MyDistribution';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Cf004CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
