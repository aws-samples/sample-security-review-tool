import { describe, it, expect, beforeEach } from 'vitest';
import { Elb002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-load-balancing/002-access-logs-enabled.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ELB-002: Enable ELB/ALB access logs', () => {
  let rule: Elb002Rule;

  beforeEach(() => {
    rule = new Elb002Rule();
  });

  it('should flag Classic ELB without access logging', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{ Protocol: 'HTTP', LoadBalancerPort: 80 }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('AccessLoggingPolicy.Enabled to true');
  });

  it('should flag ALB without access logs enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: {
        Type: 'application',
        LoadBalancerAttributes: [
          { Key: 'access_logs.s3.enabled', Value: 'false' }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('access_logs.s3.enabled to true');
  });

  it('should pass ALB with access logs enabled', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
      LogicalId: 'TestALB',
      Properties: {
        LoadBalancerAttributes: [
          { Key: 'access_logs.s3.enabled', Value: 'true' }
        ]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});