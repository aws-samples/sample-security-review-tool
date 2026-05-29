import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Cf003CfnAdapterFactory();

function runControl(template: Template, logicalId: string) {
  const resource = template.Resources![logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return cf003Control.run(adapter, context);
}

describe('CF-003 CloudFormation - REQ-09: multiple logging configurations with at least one fully valid', () => {
  it('passes when both inline logging AND external delivery chain are present and valid', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Logging: {
                Bucket: 'my-logs-bucket.s3.amazonaws.com',
                Prefix: 'cf-logs/',
                IncludeCookies: false,
              },
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
            },
          },
        },
        MyDeliverySource: {
          Type: 'AWS::Logs::DeliverySource',
          Properties: {
            Name: 'my-source',
            ResourceArn: 'MyDistribution',
            LogType: 'ACCESS_LOGS',
          },
        },
        MyDeliveryDestination: {
          Type: 'AWS::Logs::DeliveryDestination',
          Properties: {
            Name: 'my-destination',
            DestinationResourceArn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudfront/access-logs',
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'MyDistribution');
    expect(result).toBeNull();
  });

  it('passes when inline logging is valid but external delivery chain is incomplete (missing destination)', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Logging: {
                Bucket: 'my-logs-bucket.s3.amazonaws.com',
                Prefix: 'cf-logs/',
              },
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
            },
          },
        },
        MyDeliverySource: {
          Type: 'AWS::Logs::DeliverySource',
          Properties: {
            Name: 'my-source',
            ResourceArn: 'MyDistribution',
            LogType: 'ACCESS_LOGS',
          },
        },
        // No DeliveryDestination present - external chain is incomplete
      },
    } as unknown as Template;

    const result = runControl(template, 'MyDistribution');
    expect(result).toBeNull();
  });

  it('passes when inline logging is invalid (missing Bucket) but external delivery chain is complete', () => {
    const template: Template = {
      Resources: {
        MyDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              Logging: {
                // Bucket missing - inline logging is invalid
                Prefix: 'cf-logs/',
                IncludeCookies: false,
              },
              DefaultCacheBehavior: {
                TargetOriginId: 'origin1',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
            },
          },
        },
        MyDeliverySource: {
          Type: 'AWS::Logs::DeliverySource',
          Properties: {
            Name: 'my-source',
            ResourceArn: 'MyDistribution',
            LogType: 'ACCESS_LOGS',
          },
        },
        MyDeliveryDestination: {
          Type: 'AWS::Logs::DeliveryDestination',
          Properties: {
            Name: 'my-destination',
            DestinationResourceArn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudfront/access-logs',
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'MyDistribution');
    expect(result).toBeNull();
  });
});
