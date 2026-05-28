import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-07 (CloudFormation): S3 origin with legacy OAI and dangling OAC reference', () => {
  it('passes because the valid OAI supersedes the dangling OAC reference', () => {
    const template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [
                {
                  Id: 's3-origin-1',
                  DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
                  S3OriginConfig: {
                    OriginAccessIdentity: 'origin-access-identity/cloudfront/E1234567890ABC',
                  },
                  OriginAccessControlId: 'NonExistentOacLogicalId',
                },
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const logicalId = 'MyDistribution';
    const resource = (template as any).Resources[logicalId];

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

    expect(adapter.unprotectedS3Origins).toEqual([]);
    expect(result).toBeNull();
  });
});
