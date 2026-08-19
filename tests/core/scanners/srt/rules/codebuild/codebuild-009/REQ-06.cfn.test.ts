import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'secondary-source-bucket';

function policyDocument(actions: string[]): Record<string, unknown> {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: actions,
        Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
      },
    ],
  };
}

/**
 * Project's primary source is a git hosting provider; a secondary source lives in
 * an S3 bucket. The service role is defined in the same template with an inline
 * policy granting the requested actions on that bucket.
 */
function buildTemplate(actions: string[]): Template {
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
              PolicyName: 'BucketInspection',
              PolicyDocument: policyDocument(actions),
            },
          ],
        },
      },
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          // ServiceRole written as !Ref BuildRole -> resolves to the logical id
          ServiceRole: 'BuildRole',
          Artifacts: { Type: 'NO_ARTIFACTS' },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          Source: {
            Type: 'GITHUB',
            Location: 'https://github.com/example/repo.git',
            SourceIdentifier: 'primary',
          },
          SecondarySources: [
            {
              Type: 'S3',
              Location: `${BUCKET}/inputs/source.zip`,
              SourceIdentifier: 'extra',
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template, logicalId: string): CfnContext {
  const resources = template.Resources as Record<string, Resource>;
  return {
    stackName: 'codebuild-009-stack',
    template,
    resource: resources[logicalId],
    logicalId,
  };
}

function run(template: Template, logicalId: string) {
  const context = contextFor(template, logicalId);
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation) - secondary S3 source bucket covered by in-template role policy', () => {
  // Primary behaviour owned by CODEBUILD-009: both required actions present -> no finding.
  it('passes when the in-template service-role policy allows both s3:GetBucketAcl and s3:GetBucketLocation on the secondary source bucket', () => {
    const template = buildTemplate(['s3:GetBucketAcl', 's3:GetBucketLocation']);

    expect(run(template, 'BuildProject')).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - one of the required pair is absent.
  it('flags the project when the same policy allows only s3:GetBucketLocation on that bucket', () => {
    const template = buildTemplate(['s3:GetBucketLocation']);

    const result = run(template, 'BuildProject');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
