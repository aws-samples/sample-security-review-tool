import { describe, test, expect, beforeEach } from 'vitest';
import { ECS007Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/007-logging-enabled.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ECS007Rule', () => {
  let rule: ECS007Rule;

  beforeEach(() => {
    rule = new ECS007Rule();
  });

  test('should return null for non-ECS TaskDefinition resources', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::S3::Bucket',
      Properties: {},
      LogicalId: 'TestBucket'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should return null when no container definitions exist', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {},
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag ECS TaskDefinition without LogConfiguration', () => {
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
    expect(result?.fix).toContain('Configure LogConfiguration');
  });

  test('should flag ECS TaskDefinition with LogConfiguration but no LogDriver', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {}
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify a LogDriver');
  });

  test('should flag ECS TaskDefinition with non-awslogs LogDriver', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'json-file'
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Use \'awslogs\' as the LogDriver');
  });

  test('should flag ECS TaskDefinition with awslogs LogDriver but no Options', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'awslogs'
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Configure Options for the awslogs LogDriver');
  });

  test('should flag ECS TaskDefinition with awslogs LogDriver but missing awslogs-group', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'awslogs',
            Options: {
              'awslogs-region': 'us-west-2',
              'awslogs-stream-prefix': 'app'
            }
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify \'awslogs-group\'');
  });

  test('should flag ECS TaskDefinition with awslogs LogDriver but missing awslogs-region', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'awslogs',
            Options: {
              'awslogs-group': '/ecs/app',
              'awslogs-stream-prefix': 'app'
            }
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Specify \'awslogs-region\'');
  });

  test('should flag ECS TaskDefinition with awslogs LogDriver but missing awslogs-stream-prefix', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'awslogs',
            Options: {
              'awslogs-group': '/ecs/app',
              'awslogs-region': 'us-west-2'
            }
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Consider specifying \'awslogs-stream-prefix\'');
  });

  test('should not flag ECS TaskDefinition with properly configured awslogs LogDriver', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'awslogs',
            Options: {
              'awslogs-group': '/ecs/app',
              'awslogs-region': 'us-west-2',
              'awslogs-stream-prefix': 'app'
            }
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should handle multiple container definitions', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [
          {
            Name: 'AppContainer',
            Image: 'app:latest',
            Essential: true,
            LogConfiguration: {
              LogDriver: 'awslogs',
              Options: {
                'awslogs-group': '/ecs/app',
                'awslogs-region': 'us-west-2',
                'awslogs-stream-prefix': 'app'
              }
            }
          },
          {
            Name: 'SidecarContainer',
            Image: 'sidecar:latest',
            Essential: false,
            LogConfiguration: {
              LogDriver: 'awslogs',
              Options: {
                'awslogs-group': '/ecs/sidecar',
                'awslogs-region': 'us-west-2',
                'awslogs-stream-prefix': 'sidecar'
              }
            }
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag if any container definition is missing proper logging', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [
          {
            Name: 'AppContainer',
            Image: 'app:latest',
            Essential: true,
            LogConfiguration: {
              LogDriver: 'awslogs',
              Options: {
                'awslogs-group': '/ecs/app',
                'awslogs-region': 'us-west-2',
                'awslogs-stream-prefix': 'app'
              }
            }
          },
          {
            Name: 'SidecarContainer',
            Image: 'sidecar:latest',
            Essential: false
            // Missing LogConfiguration
          }
        ]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Configure LogConfiguration');
  });

  test('should handle intrinsic functions in LogConfiguration', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ContainerDefinitions: [{
          Name: 'AppContainer',
          Image: 'app:latest',
          Essential: true,
          LogConfiguration: {
            LogDriver: 'awslogs',
            Options: {
              'awslogs-group': { 'Fn::Sub': '/ecs/${AWS::StackName}' },
              'awslogs-region': { Ref: 'AWS::Region' },
              'awslogs-stream-prefix': 'app'
            }
          }
        }]
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });
});
