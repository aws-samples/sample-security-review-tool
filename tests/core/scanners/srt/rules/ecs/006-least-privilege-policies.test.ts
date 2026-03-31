import { describe, test, expect, beforeEach } from 'vitest';
import { Ecs006Rule, ECS006Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/ecs/006-least-privilege-policies.js';
import { CloudFormationResource, Resource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';
import { Template } from 'cloudform-types';

describe('Ecs006Rule', () => {
  let rule: Ecs006Rule;
  const stackName = 'TestStack';

  beforeEach(() => {
    rule = new Ecs006Rule();
  });

  describe('rule properties', () => {
    test('should have correct id and priority', () => {
      expect(rule.id).toBe('ECS-006');
      expect(rule.priority).toBe('HIGH');
    });

    test('should export both Ecs006Rule and ECS006Rule for backwards compatibility', () => {
      expect(Ecs006Rule).toBeDefined();
      expect(ECS006Rule).toBeDefined();
      expect(Ecs006Rule).toBe(ECS006Rule);
    });
  });

  describe('appliesTo', () => {
    test('should apply to AWS::ECS::TaskDefinition', () => {
      expect(rule.appliesTo('AWS::ECS::TaskDefinition')).toBe(true);
    });

    test('should apply to AWS::IAM::Role', () => {
      expect(rule.appliesTo('AWS::IAM::Role')).toBe(true);
    });

    test('should not apply to other resource types', () => {
      expect(rule.appliesTo('AWS::S3::Bucket')).toBe(false);
      expect(rule.appliesTo('AWS::Lambda::Function')).toBe(false);
    });
  });

  describe('evaluateResource', () => {
    test('should return undefined to signal use of legacy evaluate', () => {
      const template: Template = {
        Resources: {
          TestResource: { Type: 'AWS::ECS::TaskDefinition', Properties: {} }
        }
      };
      const result = rule.evaluateResource(stackName, template, template.Resources!['TestResource'] as Resource);
      expect(result).toBeUndefined();
    });
  });

  describe('evaluate', () => {
    test('should return null for non-ECS TaskDefinition or IAM Role resources', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::S3::Bucket',
        Properties: {},
        LogicalId: 'TestBucket'
      };

      const result = rule.evaluate(resource, stackName, [resource]);
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

      const result = rule.evaluate(resource, stackName);
      expect(result).toBeNull();
    });

    test('should return null for ECS TaskDefinition without TaskRoleArn', () => {
      const resource: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          ExecutionRoleArn: { Ref: 'ExecutionRole' }
        },
        LogicalId: 'TestTaskDefinition'
      };

      const result = rule.evaluate(resource, stackName, [resource]);
      expect(result).toBeNull();
    });

    test('should flag ECS TaskDefinition with TaskRoleArn that cannot be found in the template', () => {
      const resource: CloudFormationResource = {
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

      const result = rule.evaluate(resource, stackName, [resource, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Ensure the TaskRoleArn references an IAM role');
    });

    test('should flag IAM Role with no policies defined', () => {
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Define specific policies for the task role');
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Avoid using wildcard actions');
    });

    test('should flag IAM Role with service-level wildcard actions', () => {
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
                Action: 's3:*',
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Avoid using wildcard actions');
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Replace wildcard resource');
    });

    test('should flag IAM Role with wildcard resources with conditions', () => {
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Consider replacing wildcard resource');
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Replace broad AWS managed policies');
    });

    test('should flag IAM Role with too many managed policies', () => {
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
          ManagedPolicyArns: [
            'arn:aws:iam::aws:policy/AmazonS3FullAccess',
            'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
            'arn:aws:iam::aws:policy/AmazonSQSFullAccess',
            'arn:aws:iam::aws:policy/AmazonSNSFullAccess'
          ]
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Consider consolidating multiple managed policies');
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

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).toBeNull();
    });

    test('should not flag IAM Role that is not used as a task role by an ECS task', () => {
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

      const result = rule.evaluate(role, stackName, [taskDefinition, role]);
      expect(result).toBeNull();
    });

    test('should handle intrinsic functions in TaskRoleArn using Fn::GetAtt', () => {
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

      const result = rule.evaluate(taskDefinition, stackName, [taskDefinition, taskRole, executionRole]);
      expect(result).toBeNull();
    });
  });

  describe('attached policies (CDK-generated AWS::IAM::Policy resources)', () => {
    test('should not flag IAM Role with attached policy (CDK pattern)', () => {
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
          // No inline Policies or ManagedPolicyArns - CDK generates separate AWS::IAM::Policy
        },
        LogicalId: 'TaskRole'
      };

      const attachedPolicy: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'TaskRoleDefaultPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['dynamodb:GetItem', 'dynamodb:PutItem'],
              Resource: ['arn:aws:dynamodb:us-east-1:123456789012:table/MyTable']
            }]
          },
          Roles: [{ Ref: 'TaskRole' }]
        },
        LogicalId: 'TaskRoleDefaultPolicy'
      };

      const taskDefinition: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          TaskRoleArn: { 'Fn::GetAtt': ['TaskRole', 'Arn'] }
        },
        LogicalId: 'TestTaskDefinition'
      };

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, attachedPolicy]);
      expect(result).toBeNull();
    });

    test('should flag IAM Role with attached policy containing wildcard actions', () => {
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
        },
        LogicalId: 'TaskRole'
      };

      const attachedPolicy: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'TaskRoleDefaultPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 's3:*',
              Resource: ['arn:aws:s3:::my-bucket/*']
            }]
          },
          Roles: [{ Ref: 'TaskRole' }]
        },
        LogicalId: 'TaskRoleDefaultPolicy'
      };

      const taskDefinition: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          TaskRoleArn: { 'Fn::GetAtt': ['TaskRole', 'Arn'] }
        },
        LogicalId: 'TestTaskDefinition'
      };

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, attachedPolicy]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Avoid using wildcard actions');
    });

    test('should flag IAM Role with attached policy containing wildcard resources', () => {
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
        },
        LogicalId: 'TaskRole'
      };

      const attachedPolicy: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'TaskRoleDefaultPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: '*'
            }]
          },
          Roles: [{ Ref: 'TaskRole' }]
        },
        LogicalId: 'TaskRoleDefaultPolicy'
      };

      const taskDefinition: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          TaskRoleArn: { 'Fn::GetAtt': ['TaskRole', 'Arn'] }
        },
        LogicalId: 'TestTaskDefinition'
      };

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, attachedPolicy]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Replace wildcard resource');
    });

    test('should handle multiple attached policies', () => {
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
        },
        LogicalId: 'TaskRole'
      };

      const policy1: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'DynamoDBPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['dynamodb:GetItem', 'dynamodb:PutItem'],
              Resource: ['arn:aws:dynamodb:us-east-1:123456789012:table/MyTable']
            }]
          },
          Roles: [{ Ref: 'TaskRole' }]
        },
        LogicalId: 'DynamoDBPolicy'
      };

      const policy2: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'S3Policy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::my-bucket/*']
            }]
          },
          Roles: [{ Ref: 'TaskRole' }]
        },
        LogicalId: 'S3Policy'
      };

      const taskDefinition: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          TaskRoleArn: { 'Fn::GetAtt': ['TaskRole', 'Arn'] }
        },
        LogicalId: 'TestTaskDefinition'
      };

      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, policy1, policy2]);
      expect(result).toBeNull();
    });

    test('should not consider policies attached to other roles', () => {
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
        },
        LogicalId: 'TaskRole'
      };

      // This policy is attached to a different role
      const otherPolicy: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'OtherPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: ['s3:GetObject'],
              Resource: ['arn:aws:s3:::other-bucket/*']
            }]
          },
          Roles: [{ Ref: 'OtherRole' }]
        },
        LogicalId: 'OtherPolicy'
      };

      const taskDefinition: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          TaskRoleArn: { 'Fn::GetAtt': ['TaskRole', 'Arn'] }
        },
        LogicalId: 'TestTaskDefinition'
      };

      // TaskRole has no policies (inline, managed, or attached) - should flag
      const result = rule.evaluate(taskRole, stackName, [taskDefinition, taskRole, otherPolicy]);
      expect(result).not.toBeNull();
      expect(result?.fix).toContain('Define specific policies for the task role');
    });

    test('should handle CDK-style template with role and separate policy (real-world scenario)', () => {
      // This mimics the actual CDK-generated template structure
      const taskRole: CloudFormationResource = {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ecs-tasks.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }]
          }
        },
        LogicalId: 'coretaskdefinitionTaskRole634BA82C',
        Metadata: { 'aws:cdk:path': 'changelogs-md-core/core-task-definition/TaskRole/Resource' }
      };

      const defaultPolicy: CloudFormationResource = {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyDocument: {
            Statement: [
              {
                Effect: 'Allow',
                Action: [
                  'dynamodb:BatchGetItem',
                  'dynamodb:GetRecords',
                  'dynamodb:Query',
                  'dynamodb:GetItem',
                  'dynamodb:PutItem',
                  'dynamodb:UpdateItem',
                  'dynamodb:DeleteItem'
                ],
                Resource: [
                  { 'Fn::ImportValue': 'changelogs-md-resources:TableArn' },
                  { 'Fn::Join': ['', [{ 'Fn::ImportValue': 'changelogs-md-resources:TableArn' }, '/index/*']] }
                ]
              },
              {
                Effect: 'Allow',
                Action: ['s3:GetObject*', 's3:PutObject'],
                Resource: [
                  { 'Fn::ImportValue': 'changelogs-md-resources:BucketArn' },
                  { 'Fn::Join': ['', [{ 'Fn::ImportValue': 'changelogs-md-resources:BucketArn' }, '/*']] }
                ]
              }
            ],
            Version: '2012-10-17'
          },
          PolicyName: 'coretaskdefinitionTaskRoleDefaultPolicy8B6D94FD',
          Roles: [{ Ref: 'coretaskdefinitionTaskRole634BA82C' }]
        },
        LogicalId: 'coretaskdefinitionTaskRoleDefaultPolicy8B6D94FD',
        Metadata: { 'aws:cdk:path': 'changelogs-md-core/core-task-definition/TaskRole/DefaultPolicy/Resource' }
      };

      const taskDefinition: CloudFormationResource = {
        Type: 'AWS::ECS::TaskDefinition',
        Properties: {
          TaskRoleArn: { 'Fn::GetAtt': ['coretaskdefinitionTaskRole634BA82C', 'Arn'] }
        },
        LogicalId: 'coretaskdefinition9BB3B725',
        Metadata: { 'aws:cdk:path': 'changelogs-md-core/core-task-definition/Resource' }
      };

      const result = rule.evaluate(taskRole, 'changelogs-md-core', [taskDefinition, taskRole, defaultPolicy]);
      expect(result).toBeNull();
    });
  });
});
