import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 / REQ-06 (CloudFormation): dangling OriginAccessControlId reference', () => {
  it('flags an S3 origin whose OriginAccessControlId does not resolve to an OAC resource in the template', () => {
    // The template contains an S3 bucket origin and an OriginAccessControlId
    // that, after preprocessing, is the string "MissingOac". There is no
    // resource with logical ID "MissingOac" in the template, so the
    // identifier is a dangling reference. Per the resolved decision, this
    // must be flagged as non-compliant.
    const template: Template = {
      Resources: {
        SiteBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Origins: [
                {
                  Id: 'site-s3-origin',
                  // After preprocessing of !GetAtt SiteBucket.RegionalDomainName
                  // this becomes the logical id string "SiteBucket".
                  DomainName: 'SiteBucket',
                  // After preprocessing of !Ref MissingOac this becomes the
                  // string "MissingOac". No such resource exists in the
                  // template — the reference dangles.
                  OriginAccessControlId: 'MissingOac',
                },
              ],
              DefaultCacheBehavior: {
                TargetOriginId: 'site-s3-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf006CfnAdapterFactory();
    const distribution = template.Resources!['Distribution']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distribution,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('Distribution');
    expect(result?.status).toBe('Open');
  });
});
