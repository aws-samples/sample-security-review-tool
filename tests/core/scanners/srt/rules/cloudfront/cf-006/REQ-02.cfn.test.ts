import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-02 CloudFormation: S3 origin with in-template OAC reference', () => {
  it('passes when an S3 origin references an in-template OriginAccessControl by its identifier', () => {
    // After parseCfnTemplate preprocessing:
    // - !Ref MyOAC -> "MyOAC"
    // - !GetAtt MyBucket.RegionalDomainName -> "MyBucket"
    const template: Template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
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
                  DomainName: 'MyBucket', // resolved from !GetAtt MyBucket.RegionalDomainName
                  OriginAccessControlId: 'MyOAC', // resolved from !Ref MyOAC
                  S3OriginConfig: {},
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['MyDistribution']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);
    const adapter = factory.bind(context);

    const result = cf006Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
