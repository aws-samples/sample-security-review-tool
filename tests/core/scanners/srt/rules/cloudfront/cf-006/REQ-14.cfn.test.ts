import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 CloudFormation - REQ-14: S3 origin with OAC having wildcard/generic signing config', () => {
  it('passes when an S3 origin references an OAC resource that has a generic/wildcard signing+origin-type configuration', () => {
    // The OAC here uses generic/wildcard-style config:
    //  - SigningBehavior: 'no-override' (generic, not strict 'always')
    //  - SigningProtocol: 'sigv4' (only valid value, but treat as wildcard-equivalent default)
    //  - OriginAccessControlOriginType: 's3' (generic; not pinned to specific bucket)
    // The rule should NOT inspect these internal fields and should still pass.
    const template: Template = {
      Resources: {
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
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 's3-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 's3-origin',
                  DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
                  // After preprocessing, !Ref GenericOac resolves to the string "GenericOac"
                  OriginAccessControlId: 'GenericOac',
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf006CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(adapter.unprotectedS3Origins).toHaveLength(0);
    expect(adapter.unprotectedOacEligibleOrigins).toHaveLength(0);
    expect(result).toBeNull();
  });
});
