import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 CloudFormation - REQ-06: dangling OAC reference', () => {
  it('flags an S3 origin whose OriginAccessControlId does not resolve to any OAC resource in the template', () => {
    // Template has a CloudFront distribution that references "NonExistentOAC"
    // via OriginAccessControlId, but no AWS::CloudFront::OriginAccessControl
    // resource with that logical ID exists in the template.
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'my-s3-origin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'my-s3-origin',
                  DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
                  // After preprocessing, !Ref NonExistentOAC would resolve to
                  // the literal string "NonExistentOAC". Since no resource
                  // with that logical ID exists in the template, this is a
                  // dangling reference.
                  OriginAccessControlId: 'NonExistentOAC',
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
        // Note: NO AWS::CloudFront::OriginAccessControl resource present.
      },
    } as unknown as Template;

    const factory = new Cf006CfnAdapterFactory();
    const distributionResource = template.Resources!.MyDistribution;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distributionResource,
      logicalId: 'MyDistribution',
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('MyDistribution');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
