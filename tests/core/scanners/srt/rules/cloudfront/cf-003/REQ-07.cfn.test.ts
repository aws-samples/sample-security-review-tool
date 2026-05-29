import { describe, it, expect } from 'vitest';
import { cf003Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.control.js';
import { Cf003CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-003/cf-003.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-003 REQ-07 (CloudFormation): delivery source references a different distribution', () => {
  it('flags the assessed distribution when the only delivery source targets a different distribution', () => {
    const template = {
      Resources: {
        AssessedDistribution: {
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
              // No Logging configured inline
            },
          },
        },
        OtherDistribution: {
          Type: 'AWS::CloudFront::Distribution',
          Properties: {
            DistributionConfig: {
              Enabled: true,
              DefaultCacheBehavior: {
                TargetOriginId: 'origin2',
                ViewerProtocolPolicy: 'redirect-to-https',
              },
              Origins: [
                {
                  Id: 'origin2',
                  DomainName: 'other.example.com',
                  CustomOriginConfig: {
                    OriginProtocolPolicy: 'https-only',
                  },
                },
              ],
            },
          },
        },
        // Delivery source bound to OtherDistribution, NOT the assessed one
        DeliverySourceForOther: {
          Type: 'AWS::Logs::DeliverySource',
          Properties: {
            Name: 'cloudfront-logs-other',
            ResourceArn: 'OtherDistribution',
            LogType: 'ACCESS_LOGS',
          },
        },
      },
    } as unknown as Template;

    const factory = new Cf003CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      logicalId: 'AssessedDistribution',
      resource: template.Resources!.AssessedDistribution,
    };

    const adapter = factory.bind(context);
    const result = cf003Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-003');
    expect(result?.resourceName).toBe('AssessedDistribution');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.status).toBe('Open');
  });
});
