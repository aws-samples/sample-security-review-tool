import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-build-artifacts';

/**
 * Template with a CodeBuild project writing S3 artifacts to BUCKET, and a role
 * defined in the same template whose inline policy allows both bucket-inspection
 * actions on the given resource pattern.
 */
function buildTemplate(resourcePattern: string): Template {
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
              PolicyName: 'ArtifactAccess',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                    Resource: resourcePattern,
                  },
                ],
              },
            },
          ],
        },
      },
      Project: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // { Ref: 'BuildRole' } resolves to the logical id string after preprocessing
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
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['Project'],
    logicalId: 'Project',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation) - wildcard resource pattern covering the bucket itself', () => {
  // Primary behavior owned by CODEBUILD-009: a prefix wildcard that still matches the
  // plain bucket ARN grants the bucket-level actions, so no finding is reported.
  it('passes when the policy resource is a prefix wildcard that matches the bucket ARN itself', () => {
    const result = runControl(buildTemplate(`arn:aws:s3:::${BUCKET}*`));
    expect(result).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - the wildcard covers only
  // objects inside the bucket, never the plain bucket ARN.
  it('reports a finding when the wildcard covers only objects within the bucket', () => {
    const result = runControl(buildTemplate(`arn:aws:s3:::${BUCKET}/*`));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('Project');
    expect(result?.issue).toContain(BUCKET);
  });
});
