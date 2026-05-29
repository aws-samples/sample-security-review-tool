import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-05 (CloudFormation): External delivery source + destination references distribution', () => {
  it('passes (no finding) when an AWS::Logs::DeliverySource references the distribution and is paired with a delivery destination', () => {
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
              // No Logging property -> no inline access logging
            },
          },
        },
        MyDeliveryDestination: {
          Type: 'AWS::Logs::DeliveryDestination',
          Properties: {
            Name: 'cf-access-logs-destination',
            DestinationResourceArn: 'LogGroup',
          },
        },
        MyDeliverySource: {
          Type: 'AWS::Logs::DeliverySource',
          Properties: {
            Name: 'cf-access-logs-source',
            LogType: 'ACCESS_LOGS',
            // After preprocessing, !GetAtt MyDistribution.Arn -> "MyDistribution"
            ResourceArn: 'MyDistribution',
          },
        },
        MyDelivery: {
          Type: 'AWS::Logs::Delivery',
          Properties: {
            DeliverySourceName: 'cf-access-logs-source',
            DeliveryDestinationArn: 'MyDeliveryDestination',
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf003CfnAdapterFactory();
    const distributionResource = template.Resources!.MyDistribution;

    expect(factory.appliesTo(distributionResource.Type)).toBe(true);

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: distributionResource,
      logicalId: 'MyDistribution',
    };

    const adapter = factory.bind(context);
    expect(adapter.hasAccessLogging).toBe(true);

    const result = cf003Control.run(adapter, context);
    expect(result).toBeNull();
  });
});
