import { describe, it, expect, beforeEach } from 'vitest';
import { Elb004Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-load-balancing/004-multi-az-cross-zone.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ELB-004: Use at least two AZs with Cross-Zone Load Balancing', () => {
  let rule: Elb004Rule;

  beforeEach(() => {
    rule = new Elb004Rule();
  });

  it('should flag Classic ELB with single subnet', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Subnets: ['subnet-1']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer does not use multiple AZs or Cross-Zone Load Balancing is not enabled');
  });

  it('should flag Classic ELB without cross-zone load balancing', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Subnets: ['subnet-1', 'subnet-2']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer does not use multiple AZs or Cross-Zone Load Balancing is not enabled');
  });

  it('should pass Classic ELB with multiple subnets and cross-zone enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Subnets: ['subnet-1', 'subnet-2'],
        CrossZone: true
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag ALB with single subnet', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: {
        Subnets: ['subnet-1']
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer does not use multiple AZs or Cross-Zone Load Balancing is not enabled');
  });

  it('should flag ALB with multiple subnets but cross-zone disabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: {
        Subnets: ['subnet-1', 'subnet-2'],
        LoadBalancerAttributes: [
          { Key: 'load_balancing.cross_zone.enabled', Value: 'false' }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Cross-Zone Load Balancing');
  });

  it('should pass ALB with multiple subnets and cross-zone enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: {
        Subnets: ['subnet-1', 'subnet-2'],
        LoadBalancerAttributes: [
          { Key: 'load_balancing.cross_zone.enabled', Value: 'true' }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should pass ALB with multiple subnets and no explicit cross-zone setting', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: {
        Subnets: ['subnet-1', 'subnet-2']
        // No LoadBalancerAttributes - ALB defaults to cross-zone enabled
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should flag NLB with multiple subnets but no explicit cross-zone setting', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestNLB',
      Properties: {
        Type: 'network',
        Subnets: ['subnet-1', 'subnet-2']
      }
    };
    // NLBs default to cross-zone disabled, so should fail without explicit setting
    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Cross-Zone Load Balancing');
  });
});
