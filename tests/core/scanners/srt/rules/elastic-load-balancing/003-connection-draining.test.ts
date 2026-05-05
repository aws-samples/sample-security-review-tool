import { describe, it, expect, beforeEach } from 'vitest';
import { Elb003Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-load-balancing/003-connection-draining.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ELB-003: Enable connection draining for Classic Load Balancer', () => {
  let rule: Elb003Rule;

  beforeEach(() => {
    rule = new Elb003Rule();
  });

  it('should flag Classic ELB without connection draining', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {}
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('ConnectionDrainingPolicy.Enabled to true');
  });

  it('should flag Classic ELB with disabled connection draining', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        ConnectionDrainingPolicy: { Enabled: false }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
  });

  it('should pass Classic ELB with enabled connection draining', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        ConnectionDrainingPolicy: { Enabled: true, Timeout: 300 }
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});