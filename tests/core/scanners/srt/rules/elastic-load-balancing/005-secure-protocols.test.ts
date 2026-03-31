import { describe, it, expect, beforeEach } from 'vitest';
import { Elb005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-load-balancing/005-secure-protocols.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ELB-005: Use secure protocols and disable weak SSL/TLS versions', () => {
  let rule: Elb005Rule;

  beforeEach(() => {
    rule = new Elb005Rule();
  });

  it('should flag Classic ELB with HTTP protocol', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{ Protocol: 'HTTP', LoadBalancerPort: 80 }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer listener uses insecure protocols or weak SSL/TLS versions');
  });

  it('should flag Classic ELB with weak SSL policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{
          Protocol: 'HTTPS',
          LoadBalancerPort: 443,
          SSLCertificateId: 'cert-123',
          PolicyNames: ['ELBSecurityPolicy-2016-08']
        }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer listener uses insecure protocols or weak SSL/TLS versions');
  });

  it('should flag ALB listener with HTTP protocol', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::Listener',
      LogicalId: 'TestListener',
      Properties: {
        Protocol: 'HTTP',
        Port: 80
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer listener uses insecure protocols or weak SSL/TLS versions');
  });

  it('should pass HTTPS listener with secure policy', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancingV2::Listener',
      LogicalId: 'TestListener',
      Properties: {
        Protocol: 'HTTPS',
        Port: 443,
        Certificates: [{ CertificateArn: 'cert-123' }],
        SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-2021-06'
      }
    };

    const result = rule.evaluate(resource, 'test-stack');
    expect(result).toBeNull();
  });
});
