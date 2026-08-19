import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifacts-bucket';

/**
 * REQ-15 (CODEBUILD-009): a project whose artifacts live in an S3 bucket and whose
 * in-template service role is granted s3:GetBucketAcl in one statement and
 * s3:GetBucketLocation in a separate statement of the same policy document passes,
 * because IAM unions Allow statements within a document.
 */
function buildTemplate(secondStatementActions: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          // `!Ref BuildRole` resolves to the logical ID string after preprocessing.
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
            Name: 'output',
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
              PolicyName: 'build-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetBucketAcl'],
                    Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
                  },
                  {
                    Effect: 'Allow',
                    Action: secondStatementActions,
                    Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
                  },
                ],
              },
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function evaluateProject(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-15 (CloudFormation)', () => {
  it('passes when the required permissions are split across two statements of one policy document', () => {
    const result = evaluateProject(buildTemplate(['s3:GetBucketLocation']));
    expect(result).toBeNull();
  });

  // Opposite outcome: the second statement grants a different S3 action, so
  // s3:GetBucketLocation is never allowed on the artifact bucket.
  it('reports a finding when the second statement allows a different action instead of get-bucket-location', () => {
    const result = evaluateProject(buildTemplate(['s3:GetObject']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
