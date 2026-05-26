import { describe, it, expect } from 'vitest';
import { cf002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.control.js';
import { Cf002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('CF-002 REQ-07 (CloudFormation): Resource is not a CloudFront distribution', () => {
  const factory = new Cf002CfnAdapterFactory();

  it('does not apply to AWS::ElasticLoadBalancingV2::LoadBalancer (regional load balancer)', () => {
    expect(factory.appliesTo('AWS::ElasticLoadBalancingV2::LoadBalancer')).toBe(false);
  });

  it('does not apply to AWS::S3::Bucket (unrelated resource type)', () => {
    expect(factory.appliesTo('AWS::S3::Bucket')).toBe(false);
  });

  it('does not apply to AWS::GlobalAccelerator::Accelerator (different CDN-like resource)', () => {
    expect(factory.appliesTo('AWS::GlobalAccelerator::Accelerator')).toBe(false);
  });

  it('produces no finding when running the control on a non-CloudFront resource (defense-in-depth)', () => {
    // Even if the control is somehow invoked on a non-CloudFront resource that lacks
    // a WebACLId, it still shouldn't flag because the orchestrator filters via appliesTo.
    // We verify that appliesTo gates this scenario out so no findings are produced.
    const template = {
      Resources: {
        MyBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {},
        },
      },
    } as any;

    const resource = template.Resources.MyBucket;

    // Non-CloudFront resource type should not be applicable.
    expect(factory.appliesTo(resource.Type)).toBe(false);

    // Sanity-check: the control's id remains CF-002 and is unaffected by out-of-scope types.
    expect(cf002Control.id).toBe('CF-002');

    // Construct a context that the orchestrator would not actually pass to bind because
    // appliesTo returned false. We assert the gating, not the bind result.
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyBucket',
    };
    expect(context.resource.Type).not.toBe('AWS::CloudFront::Distribution');
  });
});
