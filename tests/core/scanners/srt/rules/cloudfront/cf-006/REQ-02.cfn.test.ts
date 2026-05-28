import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-02 (CloudFormation): S3 origin references in-template OAC by identifier', () => {
  it('passes when the S3 origin has OriginAccessControlId resolved from a Ref to an in-template OAC resource', () => {
    // After parseCfnTemplate preprocessing, !Ref MyOAC becomes the string "MyOAC".
    const template: Template = {
      Resources: {
        MyOAC: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'my-oac',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4',
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
                  // Resolved value of !Ref MyOAC after preprocessing
                  OriginAccessControlId: 'MyOAC',
                  S3OriginConfig: {},
                },
              ],
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

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(adapter.unprotectedS3Origins).toEqual([]);
    expect(result).toBeNull();
  });
});
