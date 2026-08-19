import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifact-bucket';
const factory = new Codebuild009CfnAdapterFactory();

/**
 * Builds a template where the project writes its artifacts to an S3 bucket and
 * runs under an in-template role whose inline policy document carries the given
 * statements. Values are written post-preprocessing: `!GetAtt BuildRole.Arn`
 * resolves to the logical id string `BuildRole`.
 */
function template(statements: unknown[]): Template {
  return {
    Resources: {
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
              PolicyName: 'build-policy',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: statements,
              },
            },
          ],
        },
      },
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
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
    },
  } as unknown as Template;
}

function contextFor(tmpl: Template): CfnContext {
  const resources = (tmpl.Resources ?? {}) as Record<string, any>;
  return {
    stackName: 'test-stack',
    template: tmpl,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
}

function run(tmpl: Template) {
  const context = contextFor(tmpl);
  const adapter = factory.bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation): S3 artifact bucket with an empty in-template role policy', () => {
  // Primary behavior owned by CODEBUILD-009: an empty statement list grants
  // nothing, so neither s3:GetBucketAcl nor s3:GetBucketLocation is held.
  it('flags a project whose in-template service role policy document has no statements', () => {
    const result = run(template([]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.resourceType).toBe('AWS::CodeBuild::Project');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: the nearest input that flips the verdict — the same role
  // policy document, still present, but now granting both required actions.
  it('does not flag a project whose in-template service role policy grants both required actions on the bucket', () => {
    const result = run(
      template([
        {
          Effect: 'Allow',
          Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
          Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
        },
      ]),
    );

    expect(result).toBeNull();
  });
});
