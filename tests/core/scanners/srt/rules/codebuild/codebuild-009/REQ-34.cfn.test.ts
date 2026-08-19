import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ARTIFACT_BUCKET = 'artifact-bucket';
const ROLE_LOGICAL_ID = 'CodeBuildServiceRole';

function template(roleActions: string[]): Template {
  return {
    Resources: {
      [ROLE_LOGICAL_ID]: {
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
              PolicyName: 'artifact-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: roleActions,
                    Resource: [
                      `arn:aws:s3:::${ARTIFACT_BUCKET}`,
                      `arn:aws:s3:::${ARTIFACT_BUCKET}/*`,
                    ],
                  },
                ],
              },
            },
          ],
        },
      },
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'my-project',
          // Literal role identifier matching the in-template role's logical ID.
          ServiceRole: ROLE_LOGICAL_ID,
          Artifacts: {
            Type: 'S3',
            Location: ARTIFACT_BUCKET,
            Name: 'build-output.zip',
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
    },
  } as unknown as Template;
}

function contextFor(tpl: Template): CfnContext {
  const resources = tpl.Resources as Record<string, any>;
  return {
    stackName: 'test-stack',
    template: tpl,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
}

function run(tpl: Template) {
  const context = contextFor(tpl);
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation) - service role bucket inspection permissions', () => {
  // Primary behaviour owned by this requirement: a literal, in-template service
  // role whose policy allows both required actions on the artifact bucket passes.
  it('passes when the literally referenced in-template role allows both s3:GetBucketAcl and s3:GetBucketLocation on the artifact bucket', () => {
    const result = run(template(['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:PutObject']));

    expect(result).toBeNull();
  });

  // Opposite outcome: identical fixture except the role allows only one of the
  // two required actions, so the pair is not satisfied.
  it('flags the project when the same role allows s3:GetBucketAcl but not s3:GetBucketLocation', () => {
    const result = run(template(['s3:GetBucketAcl', 's3:PutObject']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(ARTIFACT_BUCKET);
  });
});
