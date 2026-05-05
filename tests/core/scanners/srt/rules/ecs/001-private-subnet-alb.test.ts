import { describe, test, expect, beforeEach } from 'vitest';
import { ECS001Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/001-private-subnet-alb.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ECS001Rule', () => {
  let rule: ECS001Rule;

  beforeEach(() => {
    rule = new ECS001Rule();
  });

  test('should have correct rule properties', () => {
    expect(rule.id).toBe('ECS-001');
    expect(rule.priority).toBe('HIGH');
  });

  test('should apply only to ECS Service resources', () => {
    expect(rule.appliesTo('AWS::ECS::Service')).toBe(true);
    expect(rule.appliesTo('AWS::ECS::Cluster')).toBe(false);
    expect(rule.appliesTo('AWS::ECS::TaskDefinition')).toBe(false);
    expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
  });

  test('should return null for non-ECS resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      Properties: {},
      LogicalId: 'TestBucket'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should return null when no allResources parameter is provided', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {},
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag ECS Service without NetworkConfiguration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {},
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Configure NetworkConfiguration');
  });

  test('should flag ECS Service without AwsvpcConfiguration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {}
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Use awsvpc network mode');
  });

  test('should flag ECS Service without subnets', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {}
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify private subnets');
  });

  test('should flag ECS Service without security groups', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345']
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify security groups');
  });

  test('should flag ECS Service with AssignPublicIp ENABLED', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: 'ENABLED'
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Set AssignPublicIp to DISABLED');
  });

  test('should flag ECS Service without load balancers', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: 'DISABLED'
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Configure a load balancer');
  });

  test('should not flag properly configured ECS Service', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: 'DISABLED'
          }
        },
        LoadBalancers: [
          {
            TargetGroupArn: 'arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067',
            ContainerName: 'web',
            ContainerPort: 80
          }
        ]
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in subnets', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: { 'Fn::Split': [',', { 'Fn::ImportValue': 'PrivateSubnets' }] },
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: 'DISABLED'
          }
        },
        LoadBalancers: [
          {
            TargetGroupArn: 'arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067',
            ContainerName: 'web',
            ContainerPort: 80
          }
        ]
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in security groups', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: { 'Fn::GetAtt': ['SecurityGroup', 'GroupId'] },
            AssignPublicIp: 'DISABLED'
          }
        },
        LoadBalancers: [
          {
            TargetGroupArn: 'arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067',
            ContainerName: 'web',
            ContainerPort: 80
          }
        ]
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in AssignPublicIp', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: { 'Ref': 'AssignPublicIpParameter' }
          }
        },
        LoadBalancers: [
          {
            TargetGroupArn: 'arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067',
            ContainerName: 'web',
            ContainerPort: 80
          }
        ]
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).toBeNull();
  });
});
