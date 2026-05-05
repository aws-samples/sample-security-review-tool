import { describe, it, expect, beforeEach } from 'vitest';
import { Elb006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/elastic-load-balancing/006-secure-security-groups.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ELB-006: Associate ELB with secure security groups', () => {
  let rule: Elb006Rule;

  beforeEach(() => {
    rule = new Elb006Rule();
  });

  it('should flag ELB without security groups', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        Listeners: [{ Protocol: 'HTTP', LoadBalancerPort: 80 }]
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer security groups allow overly permissive access');
  });

  it('should flag ELB with overly permissive security group', () => {
    const elb: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        SecurityGroups: ['TestSG'],
        Listeners: [{ Protocol: 'HTTP', LoadBalancerPort: 80 }]
      }
    };

    const sg: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSG',
      Properties: {
        SecurityGroupIngress: [{
          CidrIp: '0.0.0.0/0',
          FromPort: 0,
          ToPort: 65535,
          IpProtocol: 'tcp'
        }]
      }
    };

    const result = rule.evaluate(elb, 'test-stack', [elb, sg]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Load balancer security groups allow overly permissive access');
  });

  it('should pass ELB with properly configured security group', () => {
    const elb: CloudFormationResource = {
      Type: 'AWS::ElasticLoadBalancing::LoadBalancer',
      LogicalId: 'TestELB',
      Properties: {
        SecurityGroups: ['TestSG'],
        Listeners: [{ Protocol: 'HTTP', LoadBalancerPort: 80 }]
      }
    };

    const sg: CloudFormationResource = {
      Type: 'AWS::EC2::SecurityGroup',
      LogicalId: 'TestSG',
      Properties: {
        SecurityGroupIngress: [{
          CidrIp: '10.0.0.0/8',
          FromPort: 80,
          ToPort: 80,
          IpProtocol: 'tcp'
        }]
      }
    };

    const result = rule.evaluate(elb, 'test-stack', [elb, sg]);
    expect(result).toBeNull();
  });
});
