import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 CloudFormation - REQ-01', () => {
  it('flags an S3-origin distribution that has neither OriginAccessControlId nor legacy OriginAccessIdentity', () => {
    const logicalId = 'MyDistribution';
    const resource = {
      Type: 'AWS::CloudFront::Distribution',
      Properties: {
        DistributionConfig: {
          Enabled: true,
          DefaultCacheBehavior: {
            TargetOriginId: 'S3Origin',
            ViewerProtocolPolicy: 'redirect-to-https',
          },
          Origins: [
            {
              Id: 'S3Origin',
              DomainName: 'my-bucket.s3.amazonaws.com',
              S3OriginConfig: {
                // No OriginAccessIdentity (legacy OAI) is configured
              },
              // No OriginAccessControlId is configured
            },
          ],
        },
      },
    } as any;

    const template = {
      Resources: {
        [logicalId]: resource,
      },
    } as any;

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Cf006CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);
    const adapter = factory.bind(context);

    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-006');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe(logicalId);
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
