import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 / REQ-14 (CloudFormation): S3 origin with OAC having generic/wildcard signing config', () => {
  it('passes — rule checks OAC reference resolution, not OAC internal config granularity', () => {
    const template: Template = {
      Resources: {
        SiteBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        // OAC resource configured with generic/wildcard-ish settings:
        // - SigningBehavior: 'no-override' (generic — defers to viewer)
        // - SigningProtocol: 'sigv4'
        // - OriginAccessControlOriginType: 's3' (still a valid resolvable OAC)
        GenericOac: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'generic-oac',
              SigningBehavior: 'no-override',
              SigningProtocol: 'sigv4',
              OriginAccessControlOriginType: 's3',
            },
          },
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 's3-site-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 's3-site-origin',
                  // !GetAtt SiteBucket.RegionalDomainName -> "SiteBucket" after preprocessing.
                  DomainName: 'SiteBucket',
                  S3OriginConfig: {},
                  // !Ref GenericOac -> "GenericOac" after preprocessing.
                  OriginAccessControlId: 'GenericOac',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf006CfnAdapterFactory();
    const distributionResource = template.Resources!['Distribution']!;

    expect(factory.appliesTo(distributionResource.Type)).toBe(true);

    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distributionResource,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(ctx);

    // Adapter should report no unprotected origins — the OAC reference resolves.
    expect(adapter.findS3OriginsWithoutAccessControl()).toEqual([]);

    // Control should not produce a finding.
    const result = cf006Control.run(adapter, ctx);
    expect(result).toBeNull();
  });
});
