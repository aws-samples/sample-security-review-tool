import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(distributionProperties: any): CfnContext {
  const template: any = {
    Resources: {
      MyDistribution: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: distributionProperties,
      },
    },
  };
  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources.MyDistribution,
    logicalId: 'MyDistribution',
  };
}

describe('CF-006 CFN: S3 origin with empty/unset OriginAccessControlId', () => {
  it('flags an S3 origin whose OriginAccessControlId is an empty string', () => {
    const context = buildContext({
      DistributionConfig: {
        Origins: [
          {
            Id: 'S3OriginEmptyOac',
            DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
            OriginAccessControlId: '',
            S3OriginConfig: {
              OriginAccessIdentity: '',
            },
          },
        ],
      },
    });

    const factory = new Cf006CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('MyDistribution');
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('S3OriginEmptyOac');
  });

  it('flags an S3 origin where OriginAccessControlId is omitted entirely', () => {
    const context = buildContext({
      DistributionConfig: {
        Origins: [
          {
            Id: 'S3OriginNoOac',
            DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
            S3OriginConfig: {
              OriginAccessIdentity: '',
            },
          },
        ],
      },
    });

    const factory = new Cf006CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('S3OriginNoOac');
  });

  it('flags an S3 origin where OriginAccessControlId is whitespace only', () => {
    const context = buildContext({
      DistributionConfig: {
        Origins: [
          {
            Id: 'S3OriginWhitespaceOac',
            DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
            OriginAccessControlId: '   ',
            S3OriginConfig: {
              OriginAccessIdentity: '',
            },
          },
        ],
      },
    });

    const factory = new Cf006CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(adapter.unprotectedS3Origins).toHaveLength(1);
    expect(adapter.unprotectedS3Origins[0].originId).toBe('S3OriginWhitespaceOac');
  });
});
