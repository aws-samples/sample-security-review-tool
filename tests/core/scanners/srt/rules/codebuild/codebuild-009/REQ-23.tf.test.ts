import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifacts-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET}`;

function project(): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: BUCKET }],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
    },
  } as TerraformResource;
}

function role(): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'demo-build-role' },
  } as TerraformResource;
}

function rolePolicy(secondStatementEffect: 'Deny' | 'Allow', secondStatementResource: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'artifact_bucket_access',
    address: 'aws_iam_role_policy.artifact_bucket_access',
    values: {
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
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
      }),
    },
  } as TerraformResource;
}

function runOnProject(policy: TerraformResource) {
  const projectResource = project();
  const allResources = [projectResource, role(), policy];
  const context: TfContext = {
    projectName: 'test-project',
    resource: projectResource,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform) - explicit Deny overrides the Allow on the artifacts bucket', () => {
  // Primary behavior owned by this requirement: a Deny of s3:GetBucketAcl on the
  // artifacts bucket means the role effectively lacks the permission -> flag.
  it('flags the project when a statement denies get-bucket-ACL on the same artifacts bucket that is also allowed', () => {
    const result = runOnProject(rolePolicy('Deny', BUCKET_ARN));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.resourceType).toBe('aws_codebuild_project');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: nothing denies the actions on the artifacts bucket, so the
  // Allow stands and the project complies.
  it('does not flag when the deny statement targets a different bucket, leaving both permissions effective', () => {
    const result = runOnProject(rolePolicy('Deny', 'arn:aws:s3:::some-other-bucket'));

    expect(result).toBeNull();
  });
});
