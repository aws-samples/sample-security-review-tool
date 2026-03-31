import { describe, it, expect, beforeEach } from 'vitest';
import { Batch002Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/batch/002-least-privilege-roles.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('BATCH-002: Use least-privilege IAM roles for Batch job definitions', () => {
  let rule: Batch002Rule;

  beforeEach(() => {
    rule = new Batch002Rule();
  });

  it('should flag job definition without JobRoleArn', () => {
    const resource: CloudFormationResource = {
      Type: 'AWS::Batch::JobDefinition',
      LogicalId: 'TestJobDef',
      Properties: {
        ContainerProperties: {}
      }
    };

    const result = rule.evaluate(resource, 'test-stack', []);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Batch job definition uses overly permissive IAM roles');
  });

  it('should flag job definition with overly permissive role', () => {
    const jobDef: CloudFormationResource = {
      Type: 'AWS::Batch::JobDefinition',
      LogicalId: 'TestJobDef',
      Properties: {
        ContainerProperties: {
          JobRoleArn: { Ref: 'TestRole' }
        }
      }
    };

    const role: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'TestRole',
      Properties: {
        Policies: [{
          PolicyName: 'TestPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: '*',
              Resource: '*'
            }]
          }
        }]
      }
    };

    const result = rule.evaluate(jobDef, 'test-stack', [jobDef, role]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Batch job definition uses overly permissive IAM roles');
    expect(result?.fix).toContain('"Action": ["s3:GetObject", "s3:PutObject", "logs:CreateLogGroup"');
    expect(result?.fix).toContain('"Resource": ["arn:aws:s3:::your-bucket/*", "arn:aws:logs:*:*:*"]');
  });

  it('should flag job definition with role having dangerous managed policies', () => {
    const role: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'TestRole',
      Properties: {
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/AdministratorAccess']
      }
    };

    const jobDef: CloudFormationResource = {
      Type: 'AWS::Batch::JobDefinition',
      LogicalId: 'TestJobDef',
      Properties: {
        ContainerProperties: {
          JobRoleArn: { Ref: 'TestRole' }
        }
      }
    };

    const result = rule.evaluate(jobDef, 'test-stack', [jobDef, role]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('Batch job definition uses overly permissive IAM roles');
    expect(result?.fix).toContain('Remove from "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"]');
    expect(result?.fix).toContain('["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]');
  });

  it('should pass job definition with properly scoped role', () => {
    const jobDef: CloudFormationResource = {
      Type: 'AWS::Batch::JobDefinition',
      LogicalId: 'TestJobDef',
      Properties: {
        ContainerProperties: {
          JobRoleArn: { Ref: 'TestRole' }
        }
      }
    };

    const role: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'TestRole',
      Properties: {
        Policies: [{
          PolicyName: 'TestPolicy',
          PolicyDocument: {
            Statement: [{
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::my-bucket/*'
            }]
          }
        }]
      }
    };

    const result = rule.evaluate(jobDef, 'test-stack', [jobDef, role]);
    expect(result).toBeNull();
  });
});