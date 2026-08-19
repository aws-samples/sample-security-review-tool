import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifacts-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET}`;

/**
 * The project stores artifacts in an S3 bucket and runs under a role defined in
 * the same template. `ServiceRole` is written as `!GetAtt BuildRole.Arn`, which
 * preprocessing resolves to the logical id string "BuildRole".
 */
function buildTemplate(secondStatementEffect: 'Deny' | 'Allow', secondStatementResource: string): Template {
  return {
    Resources: {
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
              PolicyName: 'artifact-bucket-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                    Resource: BUCKET_ARN,
                  },
                  {
                    Effect: secondStatementEffect,
                    Action: 's3:GetBucketAcl',
                    Resource: secondStatementResource,
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

function runOnProject(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation) - explicit Deny overrides the Allow on the artifacts bucket', () => {
  // Primary behavior owned by this requirement: a Deny of s3:GetBucketAcl on the
  // artifacts bucket means the role effectively lacks the permission -> flag.
  it('flags the project when a statement denies get-bucket-ACL on the same artifacts bucket that is also allowed', () => {
    const result = runOnProject(buildTemplate('Deny', BUCKET_ARN));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.resourceType).toBe('AWS::CodeBuild::Project');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: nothing denies the actions on the artifacts bucket, so the
  // Allow stands and the project complies.
  it('does not flag when the deny statement targets a different bucket, leaving both permissions effective', () => {
    const result = runOnProject(buildTemplate('Deny', 'arn:aws:s3:::some-other-bucket'));

    expect(result).toBeNull();
  });
});
