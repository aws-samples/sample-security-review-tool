import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const SECONDARY_BUCKET = 'my-secondary-artifact-bucket';

function buildTemplate(actions: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // No primary build output at all.
          Artifacts: { Type: 'NO_ARTIFACTS' },
          // The only associated S3 bucket: the additional (secondary) output artifact.
          SecondaryArtifacts: [
            {
              ArtifactIdentifier: 'extra',
              Type: 'S3',
              Location: SECONDARY_BUCKET,
            },
          ],
          Source: { Type: 'GITHUB', Location: 'https://github.com/example/repo.git' },
          // Resolved form of !Ref BuildRole
          ServiceRole: 'BuildRole',
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
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: actions,
                    Resource: `arn:aws:s3:::${SECONDARY_BUCKET}`,
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

function contextFor(template: Template): CfnContext {
  const resources = template.Resources as Record<string, any>;
  return {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
}

function run(template: Template) {
  const context = contextFor(template);
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 CloudFormation - secondary S3 artifact bucket with fully permitted in-template service role', () => {
  // Primary behavior owned by CODEBUILD-009: both bucket-inspection permissions granted -> compliant.
  it('passes when the in-template role allows both s3:GetBucketAcl and s3:GetBucketLocation on the secondary artifact bucket', () => {
    const result = run(buildTemplate(['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:PutObject']));

    expect(result).toBeNull();
  });

  it('flags the project when the same role grants only s3:GetBucketLocation on that bucket (opposite case)', () => {
    const result = run(buildTemplate(['s3:GetBucketLocation', 's3:PutObject']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(SECONDARY_BUCKET);
  });
});
