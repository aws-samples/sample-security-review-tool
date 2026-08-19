import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009CfnAdapterFactory();

function scan(template: Template, logicalId: string) {
  const resource = (template.Resources as Record<string, any>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

const EXTERNAL_ROLE_ARN = 'arn:aws:iam::123456789012:role/preexisting-codebuild-role';

/**
 * REQ-10 (primary): a project that writes artifacts to an S3 bucket while running
 * under a role identified only by an identifier that is not defined anywhere in the
 * template must be flagged - nothing in the template grants s3:GetBucketAcl or
 * s3:GetBucketLocation on that bucket, and AWS managed / default service roles
 * never grant them implicitly.
 */
describe('CODEBUILD-009 REQ-10 (CloudFormation)', () => {
  it('flags a project with S3 artifacts whose service role is not defined in the template', () => {
    const template: Template = {
      Resources: {
        BuildProject: {
          Type: 'AWS::CodeBuild::Project',
          Properties: {
            Name: 'artifact-writer',
            ServiceRole: EXTERNAL_ROLE_ARN,
            Artifacts: {
              Type: 'S3',
              Location: 'my-artifact-bucket',
            },
            Environment: {
              Type: 'LINUX_CONTAINER',
              ComputeType: 'BUILD_GENERAL1_SMALL',
              Image: 'aws/codebuild/standard:7.0',
            },
            Source: { Type: 'NO_SOURCE' },
          },
        },
      },
    } as unknown as Template;

    const result = scan(template, 'BuildProject');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain('my-artifact-bucket');
  });

  // Opposite outcome: identical project, except the service role IS defined in the
  // template and its inline policy allows both required actions on the same bucket.
  it('does not flag when the service role is defined in the template and grants both required permissions', () => {
    const template: Template = {
      Resources: {
        BuildProject: {
          Type: 'AWS::CodeBuild::Project',
          Properties: {
            Name: 'artifact-writer',
            ServiceRole: 'BuildRole',
            Artifacts: {
              Type: 'S3',
              Location: 'my-artifact-bucket',
            },
            Environment: {
              Type: 'LINUX_CONTAINER',
              ComputeType: 'BUILD_GENERAL1_SMALL',
              Image: 'aws/codebuild/standard:7.0',
            },
            Source: { Type: 'NO_SOURCE' },
          },
        },
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
            Policies: [
              {
                PolicyName: 'bucket-inspection',
                PolicyDocument: {
                  Version: '2012-10-17',
                  Statement: [
                    {
                      Effect: 'Allow',
                      Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                      Resource: [
                        'arn:aws:s3:::my-artifact-bucket',
                        'arn:aws:s3:::my-artifact-bucket/*',
                      ],
                    },
                  ],
                },
              },
            ],
          },
        },
      },
    } as unknown as Template;

    expect(scan(template, 'BuildProject')).toBeNull();
  });
});
