import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 CloudFormation - REQ-08: multi-origin distribution with all S3 origins protected by OAC and remaining origins non-OAC-eligible', () => {
  it('passes when every S3 origin has a resolved OAC reference and other origins are custom HTTP origins', () => {
    const template: Template = {
      Resources: {
        S3OacOne: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'oac-one',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4',
            },
          },
        },
        S3OacTwo: {
          Type: 'AWS::CloudFront::OriginAccessControl',
          Properties: {
            OriginAccessControlConfig: {
              Name: 'oac-two',
              OriginAccessControlOriginType: 's3',
              SigningBehavior: 'always',
              SigningProtocol: 'sigv4',
            },
          },
        },
        Distribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 's3-origin-one',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 's3-origin-one',
                  DomainName: 'bucket-one.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {},
                  OriginAccessControlId: 'S3OacOne',
                },
                {
                  Id: 's3-origin-two',
                  DomainName: 'bucket-two.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {},
                  OriginAccessControlId: 'S3OacTwo',
                },
                {
                  Id: 'custom-http-origin',
                  DomainName: 'api.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                    HTTPPort: 80,
                    HTTPSPort: 443,
                  },
                },
                {
                  Id: 'another-custom-http-origin',
                  DomainName: 'legacy.example.org',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.Distribution,
      logicalId: 'Distribution',
    };

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(adapter.unprotectedS3Origins).toEqual([]);
    expect(result).toBeNull();
  });
});
