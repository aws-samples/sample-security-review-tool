import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';
const AWS_MANAGED_POLICY_ARN = 'arn:aws:iam::aws:policy/AWSCodeBuildDeveloperAccess';

const factory = new Codebuild009CfnAdapterFactory();

function project(): Record<string, unknown> {
  return {
    Type: 'AWS::CodeBuild::Project',
    Properties: {
      Name: 'build-project',
      // !Ref BuildRole resolves to the logical id string after preprocessing
      ServiceRole: 'BuildRole',
      Artifacts: {
        Type: 'S3',
        Location: BUCKET,
      },
      Source: {
        Type: 'GITHUB',
        Location: 'https://github.com/example/repo.git',
      },
      Environment: {
        Type: 'LINUX_CONTAINER',
        ComputeType: 'BUILD_GENERAL1_SMALL',
        Image: 'aws/codebuild/standard:7.0',
      },
    },
  };
}

function run(template: Template, logicalId: string) {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 (CloudFormation): service role permissions for associated S3 buckets', () => {
  // Primary behaviour owned by this requirement: an AWS-provided managed policy is
  // known not to grant s3:GetBucketAcl / s3:GetBucketLocation, and its contents are
  // not in the template, so a role whose only permissions come from it must be flagged.
  it('flags a project whose service role only carries a service-provided managed policy', () => {
    const template = {
      Resources: {
        BuildProject: project(),
        BuildRole: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: { Service: 'codebuild.amazonaws.com' },
                  Action: 'sts:AssumeRole',
                },
              ],
            },
            ManagedPolicyArns: [AWS_MANAGED_POLICY_ARN],
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'BuildProject');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: identical project and role, except the role's permissions are
  // present in the template and explicitly allow both required actions on the bucket.
  it('does not flag when the same role explicitly allows both bucket-inspection actions', () => {
    const template = {
      Resources: {
        BuildProject: project(),
        BuildRole: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: { Service: 'codebuild.amazonaws.com' },
                  Action: 'sts:AssumeRole',
                },
              ],
            },
            ManagedPolicyArns: [AWS_MANAGED_POLICY_ARN],
            Policies: [
              {
                PolicyName: 'BucketInspection',
                PolicyDocument: {
                  Version: '2012-10-17',
                  Statement: [
                    {
                      Effect: 'Allow',
                      Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                      Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
                    },
                    {
                      Effect: 'Allow',
                      Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                      Resource: '*',
                    },
                  ],
                },
              },
            ],
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'BuildProject')).toBeNull();
  });
});
