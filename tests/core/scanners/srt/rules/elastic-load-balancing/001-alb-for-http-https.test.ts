import { describe, it, expect, beforeEach } from 'vitest';
import { Elb001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-load-balancing/001-alb-for-http-https.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ELB-001: Use ALB for HTTP/HTTPS applications', () => {
  let rule: Elb001Rule;

  beforeEach(() => {
    rule = new Elb001Rule();
  });

  it('should flag Classic ELB with HTTP listener', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{ Protocol: 'HTTP', LoadBalancerPort: 80 }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Classic Load Balancer is used for HTTP/HTTPS traffic');
  });

  it('should flag Classic ELB with HTTPS listener', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{ Protocol: 'HTTPS', LoadBalancerPort: 443 }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Classic Load Balancer is used for HTTP/HTTPS traffic');
  });

  it('should not flag Classic ELB with TCP listener', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{ Protocol: 'TCP', LoadBalancerPort: 1433 }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });

  it('should not flag ALB', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: { Type: 'application' }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});