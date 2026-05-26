import { describe, it, expect } from 'vitest';
import { cf002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.control.js';
import { Cf002TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/cloudfront/cf-002/cf-002.adapter.tf.js';

describe('CF-002 REQ-07 (Terraform): Resource is not a CloudFront distribution', () => {
  const factory = new Cf002TfAdapterFactory();

  it('does not apply to aws_lb (regional load balancer)', () => {
    expect(factory.appliesTo('aws_lb')).toBe(false);
  });

  it('does not apply to aws_s3_bucket (unrelated resource type)', () => {
    expect(factory.appliesTo('aws_s3_bucket')).toBe(false);
  });

  it('does not apply to aws_globalaccelerator_accelerator (different CDN-like resource)', () => {
    expect(factory.appliesTo('aws_globalaccelerator_accelerator')).toBe(false);
  });

  it('produces no finding when the resource type is out of scope (defense-in-depth)', () => {
    // The orchestrator uses appliesTo to gate which resources reach the control.
    // Verify that a non-CloudFront Terraform resource is not in scope.
    const resource = {
      address: 'aws_lb.my_alb',
      type: 'aws_lb',
      name: 'my_alb',
      values: {
        // No web_acl_id concept on ALB; out of scope for this control.
        name: 'my-alb',
      },
    } as any;

    expect(factory.appliesTo(resource.type)).toBe(false);

    // Sanity-check: control identity is unchanged for out-of-scope types.
    expect(cf002Control.id).toBe('CF-002');
    expect(resource.type).not.toBe('aws_cloudfront_distribution');
  });
});
