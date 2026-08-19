import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-output-bucket';

/**
 * REQ-13 (CODEBUILD-009 owns this behavior):
 * A project storing artifacts in an S3 bucket whose in-template service role only
 * grants object-level read/write permissions on that bucket must be flagged, because
 * s3:GetBucketAcl and s3:GetBucketLocation are absent.
 */
function template(statements: unknown[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'build-project',
          // ServiceRole written as !GetAtt BuildRole.Arn resolves to the logical id.
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
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
            Type: 'LINUX_CONTAINER',
          },
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
              PolicyName: 'artifact-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: statements,
              },
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function contextFor(tpl: Template): CfnContext {
  return {
    stackName: 'test-stack',
    template: tpl,
    resource: (tpl.Resources as Record<string, any>)['BuildProject'],
    logicalId: 'BuildProject',
  };
}

function run(tpl: Template) {
  const context = contextFor(tpl);
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

const OBJECT_ONLY_STATEMENT = {
  Effect: 'Allow',
  Action: ['s3:GetObject', 's3:GetObjectVersion', 's3:PutObject'],
  Resource: `arn:aws:s3:::${BUCKET}/*`,
};

const BUCKET_LEVEL_STATEMENT = {
  Effect: 'Allow',
  Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
  Resource: `arn:aws:s3:::${BUCKET}`,
};

describe('CODEBUILD-009 REQ-13 (CloudFormation)', () => {
  it('flags a project whose in-template service role grants only object-level permissions on the artifact bucket', () => {
    const result = run(template([OBJECT_ONLY_STATEMENT]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });

  it('does not flag the same project when the role additionally grants the bucket-level inspection actions', () => {
    // Opposite outcome: only the presence of s3:GetBucketAcl / s3:GetBucketLocation changes.
    const result = run(template([OBJECT_ONLY_STATEMENT, BUCKET_LEVEL_STATEMENT]));

    expect(result).toBeNull();
  });
});
