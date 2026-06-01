import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 / CloudFormation / REQ-01', () => {
  it('flags an S3 origin distribution with no OAC and no legacy OAI configured', () => {
    const template: Template = {
      Resources: {
        OriginBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
        Distribution: {
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
                  DomainName: 'OriginBucket',
                  S3OriginConfig: {
                    // No OriginAccessIdentity (legacy OAI absent)
                    OriginAccessIdentity: '',
                  },
                  // No OriginAccessControlId (no OAC)
                },
              ],
            },
          },
        },
      },
    };

    const resource = template.Resources!['Distribution'];
    const factory = new Cf006CfnAdapterFactory();

    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'Distribution',
    };

    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CF-006');
    expect(result!.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result!.resourceName).toBe('Distribution');
    expect(result!.status).toBe('Open');
  });
});
