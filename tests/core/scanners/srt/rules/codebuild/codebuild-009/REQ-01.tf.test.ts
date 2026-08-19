import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifacts-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET}`;

function policyDocument(actions: string[]): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: actions,
        Resource: BUCKET_ARN,
      },
    ],
  });
}

/**
 * Project whose only S3 association is its artifacts bucket, running under a
 * role declared in the same project whose inline policy allows the given
 * actions on that bucket. No statement denies anything.
 */
function buildResources(allowedActions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: BUCKET, name: 'output.zip' }],
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    },
  };

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: {
      name: 'demo-build-role',
      assume_role_policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: 'codebuild.amazonaws.com' },
            Action: 'sts:AssumeRole',
          },
        ],
      }),
    },
  };

  const rolePolicy: TerraformResource = {
    type: 'aws_iam_role_policy',
    name: 'artifacts_access',
    address: 'aws_iam_role_policy.artifacts_access',
    values: {
      name: 'artifacts-access',
      role: 'aws_iam_role.build',
      policy: policyDocument(allowedActions),
    },
  };

  return [project, role, rolePolicy];
}

function runOnProject(allResources: TerraformResource[]) {
  const factory = new Codebuild009TfAdapterFactory();
  const project = allResources.find(r => r.type === 'aws_codebuild_project')!;
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  const adapter = factory.bind(context);
  return codebuild009Control.run(adapter as any, context);
}

describe('CODEBUILD-009 (Terraform) - role must allow s3:GetBucketAcl and s3:GetBucketLocation on associated bucket', () => {
  // Primary behaviour owned by this requirement: both required permissions allowed => pass
  it('passes when the in-project role policy allows both get-bucket-ACL and get-bucket-location on the artifacts bucket', () => {
    const resources = buildResources(['s3:GetBucketAcl', 's3:GetBucketLocation']);
    expect(runOnProject(resources)).toBeNull();
  });

  // Opposite outcome: same fixture, but only one of the two required permissions is allowed
  it('flags the project when the role policy allows get-bucket-ACL but not get-bucket-location on that bucket', () => {
    const resources = buildResources(['s3:GetBucketAcl']);
    const result = runOnProject(resources);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
  });
});
