import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-07 CloudFormation: S3 origin with legacy OAI and dangling OAC reference', () => {
  it('passes when an S3 origin specifies both a legacy OriginAccessIdentity and a dangling OriginAccessControlId', () => {
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
                  Id: 'S3Origin',
                  DomainName: 'SiteBucket',
                  // Dangling OAC reference: no AWS::CloudFront::OriginAccessControl
                  // resource named "NonExistentOac" exists in the template.
                  OriginAccessControlId: 'NonExistentOac',
                  S3OriginConfig: {
                    // Legacy OAI is present and non-empty.
                    OriginAccessIdentity: 'origin-access-identity/cloudfront/E1ABCDEFGHIJKL',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const factory = new Cf006CfnAdapterFactory();
    const distribution = template.Resources!['Distribution'];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distribution,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
