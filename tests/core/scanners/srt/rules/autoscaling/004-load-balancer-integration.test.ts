import { describe, it, expect } from 'vitest';
import { AS004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/autoscaling/004-load-balancer-integration.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('AS004Rule', () => {
  const rule = new AS004Rule();

  it('should pass when TargetGroupARNs is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when LoadBalancerNames is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        LoadBalancerNames: ['my-load-balancer']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass when both TargetGroupARNs and LoadBalancerNames are configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        TargetGroupARNs: ['arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-targets/1234567890123456'],
        LoadBalancerNames: ['my-load-balancer']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should fail when neither TargetGroupARNs nor LoadBalancerNames is configured', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        MinSize: 1,
        MaxSize: 3
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('is not integrated with any load balancer');
  });

  it('should fail when TargetGroupARNs is empty array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        TargetGroupARNs: []
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('is not integrated with any load balancer');
  });

  it('should fail when LoadBalancerNames is empty array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::AutoScaling::AutoScalingGroup',
      LogicalId: 'TestASG',
      Properties: {
        LoadBalancerNames: []
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('is not integrated with any load balancer');
  });

  it('should return null for non-AutoScaling resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::EC2::Instance',
      LogicalId: 'TestInstance',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});