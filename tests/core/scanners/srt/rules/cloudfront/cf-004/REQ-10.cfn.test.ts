import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 CloudFormation - REQ-10: distribution missing default viewer protocol policy and no cache behaviors collection', () => {
  it('flags the distribution with the missing-default-viewer-protocol-policy scenario', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin-1',
                // No ViewerProtocolPolicy set
              },
              // No CacheBehaviors collection populated
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

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-004');
    expect(result!.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result!.resourceName).toBe('MyDistribution');
    expect(result!.status).toBe('Open');
    expect(result!.issue).toBe(
      'CloudFront distribution default cache behavior does not specify a viewer protocol policy, allowing plaintext HTTP traffic.'
    );
    expect(result!.fix).toBe(
      'Enforce HTTPS on the distribution default cache behavior by requiring viewers to use HTTPS or be redirected to HTTPS.'
    );
  });
});
