import { describe, it, expect, beforeEach } from 'vitest';
import { CodeBuild009Rule } from '../../../../../../src/assess/scanning/security-matrix/rules/codebuild/009-s3-bucket-permissions.cf.js';
import { CloudFormationResource } from '../../../../../../src/assess/scanning/security-matrix/security-rule-base.js';

describe('CODEBUILD-009: Include required S3 permissions in CodeBuild IAM roles', () => {
  let rule: CodeBuild009Rule;

  beforeEach(() => {
    rule = new CodeBuild009Rule();
  });

  it('should flag project with role missing S3 permissions', () => {
    const project: CloudFormationResource = {
      Type: 'AWS::CodeBuild::Project',
      LogicalId: 'TestProject',
      Properties: {
        ServiceRole: { Ref: 'TestRole' }
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
              Action: 'logs:*',
              Resource: '*'
            }]
          }
        }]
      }
    };

    const result = rule.evaluate(project, 'test-stack', [project, role]);
    expect(result).not.toBeNull();
    expect(result?.issue).toContain('CodeBuild IAM role missing required S3 bucket permissions');
    expect(result?.fix).toContain('s3:GetBucketAcl');
    expect(result?.fix).toContain('s3:GetBucketLocation');
  });

  it('should pass project with role having required S3 permissions', () => {
    const project: CloudFormationResource = {
      Type: 'AWS::CodeBuild::Project',
      LogicalId: 'TestProject',
      Properties: {
        ServiceRole: { Ref: 'TestRole' }
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
              Action: ['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:GetObject'],
              Resource: '*'
            }]
          }
        }]
      }
    };

    const result = rule.evaluate(project, 'test-stack', [project, role]);
    expect(result).toBeNull();
  });

  it('should pass project with CodeBuild managed policy', () => {
    const project: CloudFormationResource = {
      Type: 'AWS::CodeBuild::Project',
      LogicalId: 'TestProject',
      Properties: {
        ServiceRole: { Ref: 'TestRole' }
      }
    };

    const role: CloudFormationResource = {
      Type: 'AWS::IAM::Role',
      LogicalId: 'TestRole',
      Properties: {
        ManagedPolicyArns: ['arn:aws:iam::aws:policy/AWSCodeBuildDeveloperAccess']
      }
    };

    const result = rule.evaluate(project, 'test-stack', [project, role]);
    expect(result).toBeNull();
  });
});