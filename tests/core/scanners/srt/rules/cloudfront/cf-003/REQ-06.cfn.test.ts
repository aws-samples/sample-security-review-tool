import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-06 (CloudFormation): external log delivery source without paired destination', () => {
  it('flags a distribution when a DeliverySource references it but no DeliveryDestination exists in the template', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'origin1',
                  DomainName: 'example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
              // No Logging block — no inline access logging configured
            },
          },
        },
        // External log delivery SOURCE referencing the distribution
        DistributionLogSource: {
          Type: 'AWS::Logs::DeliverySource',
          Properties: {
            Name: 'cloudfront-access-log-source',
            LogType: 'ACCESS_LOGS',
            ResourceArn: 'MyDistribution',
          },
        },
        // NOTE: No AWS::Logs::DeliveryDestination resource is present.
        // Per strict mode, the chain (source + destination) is incomplete.
      },
    } as unknown as Template;

    const factory = new Cf003CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyDistribution,
      logicalId: 'MyDistribution',
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-003');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe('MyDistribution');
    expect(result?.status).toBe('Open');
  });
});
