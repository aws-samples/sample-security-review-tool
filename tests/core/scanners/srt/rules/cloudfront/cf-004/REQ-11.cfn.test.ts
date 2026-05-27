import { describe, it, expect } from 'vitest';
import { cf004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.control.js';
import { Cf004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-004/cf-004.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-004 CloudFormation - REQ-11: Default cache behavior allow-all with compliant additional behaviors', () => {
  it('flags the distribution because the default cache behavior is allow-all even when additional behaviors enforce HTTPS', () => {
    const logicalId = 'NonCompliantDistribution';
    const resource = {
      Type: 'AWS::CloudFront::Distribution',
      Properties: {
        DistributionConfig: {
          Enabled: true,
          DefaultCacheBehavior: {
            TargetOriginId: 'origin1',
            ViewerProtocolPolicy: 'allow-all',
          },
          CacheBehaviors: [
            {
              PathPattern: '/api/*',
              TargetOriginId: 'origin1',
              ViewerProtocolPolicy: 'redirect-to-https',
            },
            {
              PathPattern: '/secure/*',
              TargetOriginId: 'origin1',
              ViewerProtocolPolicy: 'https-only',
            },
          ],
          Origins: [
            {
              Id: 'origin1',
              DomainName: 'example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: 'https-only',
              },
            },
          ],
        },
      },
    };

    const template = {
      Resources: {
        [logicalId]: resource,
      },
    } as unknown as CfnContext['template'];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: resource as unknown as CfnContext['resource'],
      logicalId,
    };

    const factory = new Cf004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::CloudFront::Distribution')).toBe(true);

    const adapter = factory.bind(context);
    const result = cf004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CF-004');
    expect(result?.resourceType).toBe('AWS::CloudFront::Distribution');
    expect(result?.resourceName).toBe(logicalId);
    expect(result?.status).toBe('Open');
    expect(result?.issue).toContain('default cache behavior');
    expect(result?.issue?.toLowerCase()).toContain('http');
  });
});
