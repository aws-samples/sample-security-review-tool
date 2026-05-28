import { describe, it, expect } from 'vitest';
import { cf006Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.control.js';
import { Cf006CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-006/cf-006.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-006 REQ-05 CloudFormation: S3 origin with unresolvable OriginAccessControlId', () => {
  it('passes when OriginAccessControlId is an unresolved Fn::If intrinsic', () => {
    // After preprocessing, Fn::If remains as an opaque object since it depends
    // on a Condition that cannot be evaluated at analysis time. The rule should
    // treat the value as "present but unknown" and not assert non-compliance.
    const template: any = {
      Conditions: {
        UseOac: { 'Fn::Equals': [{ Ref: 'EnableOac' }, 'true'] },
      },
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Origins: [
                {
                  Id: 's3-origin-1',
                  DomainName: 'my-bucket.s3.us-east-1.amazonaws.com',
                  OriginAccessControlId: {
                    'Fn::If': ['UseOac', 'oac-abc123', { Ref: 'AWS::NoValue' }],
                  },
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
      resource: template.Resources.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const factory = new Cf006CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = cf006Control.run(adapter, context);

    expect(result).toBeNull();
    expect(adapter.unprotectedS3Origins).toHaveLength(0);
  });
});
