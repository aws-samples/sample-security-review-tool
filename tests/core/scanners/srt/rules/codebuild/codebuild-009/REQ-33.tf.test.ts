import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';
const BUCKET_ARNS = [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`];

function resources(actions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'build',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: BUCKET, name: 'build-output' }],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
    },
  };

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: {
      name: 'codebuild-service-role',
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
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      name: 'artifact-bucket-access',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: actions,
            Resource: BUCKET_ARNS,
          },
        ],
      }),
    },
  };

  return [project, role, rolePolicy];
}

function run(actions: string[]) {
  const allResources = resources(actions);
  const context: TfContext = {
    projectName: 'test-project',
    resource: allResources[0],
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform) - wildcard action patterns grant the required bucket-inspection permissions', () => {
  // Primary behaviour owned by CODEBUILD-009: exact GetBucketAcl plus a
  // wildcard covering GetBucketLocation, both scoped to the artifact bucket.
  it('passes when get-bucket-ACL is named exactly and get-bucket-location is covered by a wildcard action', () => {
    const result = run(['s3:GetBucketAcl', 's3:GetBucket*']);
    expect(result).toBeNull();
  });

  // Opposite outcome: the wildcard is still present but does not match
  // s3:GetBucketLocation, so the permission is not effectively granted.
  it('flags when the wildcard action pattern does not match get-bucket-location', () => {
    const result = run(['s3:GetBucketAcl', 's3:GetObject*']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });
});
