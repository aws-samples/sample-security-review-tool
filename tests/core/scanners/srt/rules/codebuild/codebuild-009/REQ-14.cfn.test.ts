import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-output-bucket';

const factory = new Codebuild009CfnAdapterFactory();

function runOnProject(template: Template) {
  const resource = (template.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'BuildProject',
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

function template(roleProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // ServiceRole written as !Ref BuildRole resolves to the logical id string.
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
      },
      BuildRole: {
        Type: 'AWS::IAM::Role',
        Properties: roleProperties,
      },
    },
  } as unknown as Template;
}

const TRUST_ONLY = {
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
};

describe('CODEBUILD-009 (CloudFormation): service role must grant s3:GetBucketAcl and s3:GetBucketLocation on associated buckets', () => {
  // Primary behavior owned by CODEBUILD-009: trust policy only, no permission policies at all.
  it('flags a project whose S3 artifact bucket is used by a role that has only a trust policy', () => {
    const result = runOnProject(template(TRUST_ONLY));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: identical project, role additionally embeds the two required permissions.
  it('does not flag when the same role embeds an inline policy allowing both required actions', () => {
    const result = runOnProject(
      template({
        ...TRUST_ONLY,
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
              ],
            },
          },
        ],
      }),
    );

    expect(result).toBeNull();
  });
});
