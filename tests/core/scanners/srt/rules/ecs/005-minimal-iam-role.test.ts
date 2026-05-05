import { describe, test, expect, beforeEach } from 'vitest';
import { ECS005Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/005-minimal-iam-role.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('ECS005Rule', () => {
  let rule: ECS005Rule;

  beforeEach(() => {
    rule = new ECS005Rule();
  });

  test('should return null for non-ECS TaskDefinition or IAM Role resources', () => {
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
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack');
    expect(result).toBeNull();
  });

  test('should flag ECS TaskDefinition without TaskRoleArn', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Define a TaskRoleArn');
  });

  test('should flag ECS TaskDefinition without ExecutionRoleArn', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Define an ExecutionRoleArn');
  });

  test('should flag ECS TaskDefinition with roles that cannot be found in the template', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: 'arn:aws:iam::123456789012:role/task-role',
        ExecutionRoleArn: 'arn:aws:iam::123456789012:role/execution-role'
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(resource, 'TestStack', [resource]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Ensure TaskRoleArn and ExecutionRoleArn reference IAM roles');
  });

  test('should flag IAM Role with wildcard actions', () => {
    const taskRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        Policies: [{
          PolicyName: 'TaskPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: '*',
              Resource: ['arn:aws:s3:::my-bucket/*']
            }]
          }
        }]
      },
      LogicalId: 'TaskRole'
    };

    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' },
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const executionRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']
      },
      LogicalId: 'ExecutionRole'
    };

    const result = rule.evaluate(taskRole, 'TestStack', [taskDefinition, taskRole, executionRole]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Avoid using wildcard');
  });

  test('should flag IAM Role with wildcard resources without conditions', () => {
    const taskRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        Policies: [{
          PolicyName: 'TaskPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: '*'
            }]
          }
        }]
      },
      LogicalId: 'TaskRole'
    };

    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' },
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const executionRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']
      },
      LogicalId: 'ExecutionRole'
    };

    const result = rule.evaluate(taskRole, 'TestStack', [taskDefinition, taskRole, executionRole]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Avoid using wildcard');
  });

  test('should not flag IAM Role with wildcard resources with conditions', () => {
    const taskRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        Policies: [{
          PolicyName: 'TaskPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: '*',
              Condition: {
                StringEquals: {
                  's3:prefix': ['my-prefix']
                }
              }
            }]
          }
        }]
      },
      LogicalId: 'TaskRole'
    };

    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' },
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const executionRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']
      },
      LogicalId: 'ExecutionRole'
    };

    const result = rule.evaluate(taskRole, 'TestStack', [taskDefinition, taskRole, executionRole]);
    expect(result).toBeNull();
  });

  test('should flag IAM Role with overly permissive managed policies', () => {
    const taskRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/AdministratorAccess']
      },
      LogicalId: 'TaskRole'
    };

    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' },
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const executionRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']
      },
      LogicalId: 'ExecutionRole'
    };

    const result = rule.evaluate(taskRole, 'TestStack', [taskDefinition, taskRole, executionRole]);
    expect(result).not.toBeNull();
    expect(result?.fix).toContain('Avoid using overly permissive managed policies');
  });

  test('should not flag IAM Role with appropriate permissions', () => {
    const taskRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        Policies: [{
          PolicyName: 'TaskPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::my-bucket/*']
            }]
          }
        }]
      },
      LogicalId: 'TaskRole'
    };

    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' },
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const executionRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']
      },
      LogicalId: 'ExecutionRole'
    };

    const result = rule.evaluate(taskRole, 'TestStack', [taskDefinition, taskRole, executionRole]);
    expect(result).toBeNull();
  });

  test('should not flag IAM Role that is not used by an ECS task', () => {
    const role: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ec2.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        Policies: [{
          PolicyName: 'Policy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: '*',
              Resource: '*'
            }]
          }
        }]
      },
      LogicalId: 'Role'
    };

    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { Ref: 'TaskRole' },
        ExecutionRoleArn: { Ref: 'ExecutionRole' }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const result = rule.evaluate(role, 'TestStack', [taskDefinition, role]);
    expect(result).toBeNull();
  });

  test('should handle intrinsic functions in TaskRoleArn', () => {
    const taskDefinition: CloudFormationResource = {
      Type: 'AWS::ECS::TaskDefinition',
      Properties: {
        TaskRoleArn: { 'Fn::GetAtt': ['TaskRole', 'Arn'] },
        ExecutionRoleArn: { 'Fn::GetAtt': ['ExecutionRole', 'Arn'] }
      },
      LogicalId: 'TestTaskDefinition'
    };

    const taskRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        Policies: [{
          PolicyName: 'TaskPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::my-bucket/*']
            }]
          }
        }]
      },
      LogicalId: 'TaskRole'
    };

    const executionRole: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole'
          }]
        },
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']
      },
      LogicalId: 'ExecutionRole'
    };

    const result = rule.evaluate(taskDefinition, 'TestStack', [taskDefinition, taskRole, executionRole]);
    expect(result).toBeNull();
  });
});
