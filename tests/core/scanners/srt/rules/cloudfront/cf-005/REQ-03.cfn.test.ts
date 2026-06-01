import { describe, it, expect } from 'vitest';
import { Template } from 'cloudform-types';
import { cf005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.control.js';
import { Cf005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-005/cf-005.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-005 REQ-03 (CloudFormation): custom origin uses HTTP-only protocol policy', () => {
  it('flags a distribution whose custom origin is configured with OriginProtocolPolicy: http-only', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'customOrigin',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'customOrigin',
                  DomainName: 'example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'http-only',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const logicalId = 'MyDistribution';
    const resource = template.Resources![logicalId];
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Cf005CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);
    const adapter = factory.bind(context);

    const result = cf005Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-005');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe(logicalId);
    expect(result?.status).toBe('Open');
  });
});
