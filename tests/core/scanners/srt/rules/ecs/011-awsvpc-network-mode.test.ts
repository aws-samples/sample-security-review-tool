import { describe, test, expect, beforeEach } from 'vitest';
import { ECS011Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/011-awsvpc-network-mode.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ECS011Rule', () => {
  let rule: ECS011Rule;

  beforeEach(() => {
    rule = new ECS011Rule();
  });

  test('should return null for non-ECS TaskDefinition or Service resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      Properties: {},
      LogicalId: 'TestBucket'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag ECS TaskDefinition without NetworkMode', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify NetworkMode as \'awsvpc\'');
  });

  test('should flag ECS TaskDefinition with non-awsvpc NetworkMode', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'bridge',
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Change NetworkMode from \'bridge\' to \'awsvpc\'');
  });

  test('should not flag ECS TaskDefinition with awsvpc NetworkMode', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag ECS Service without NetworkConfiguration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Configure NetworkConfiguration');
  });

  test('should flag ECS Service without AwsvpcConfiguration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {}
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Configure AwsvpcConfiguration');
  });

  test('should flag ECS Service without subnets', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            SecurityGroups: ['sg-12345']
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify at least one subnet');
  });

  test('should flag ECS Service with empty subnets array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: [],
            SecurityGroups: ['sg-12345']
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify at least one subnet');
  });

  test('should flag ECS Service without security groups', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345']
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify at least one security group');
  });

  test('should flag ECS Service with empty security groups array', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: []
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify at least one security group');
  });

  test('should flag ECS Service with AssignPublicIp ENABLED', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
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

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
  });

  test('should not flag ECS Service with properly configured AwsvpcConfiguration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
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

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should not flag ECS Service with properly configured AwsvpcConfiguration without AssignPublicIp', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: ['sg-12345']
            // AssignPublicIp defaults to DISABLED if not specified
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in NetworkMode', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        NetworkMode: { 'Fn::Sub': 'awsvpc' },
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in Subnets', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: { 'Fn::Split': [',', { 'Fn::ImportValue': 'PrivateSubnets' }] },
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: 'DISABLED'
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in SecurityGroups', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: { 'Fn::GetAtt': ['SecurityGroup', 'GroupId'] },
            AssignPublicIp: 'DISABLED'
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in AssignPublicIp', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::Service',
      Properties: {
        TaskDefinition: { Ref: 'TaskDefinition' },
        Cluster: { Ref: 'Cluster' },
        DesiredCount: 1,
        NetworkConfiguration: {
          AwsvpcConfiguration: {
            Subnets: ['subnet-12345'],
            SecurityGroups: ['sg-12345'],
            AssignPublicIp: { Ref: 'AssignPublicIp' }
          }
        }
      },
      LogicalId: 'TestService'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });
});
