import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-output-bucket';

function project(): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      // `service_role = aws_iam_role.build.arn` collapses to the role address.
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
  } as unknown as TerraformResource;
}

function role(): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'demo-build-role' },
  } as unknown as TerraformResource;
}

function rolePolicy(bucketActions: string[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      name: 'artifact-access',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: bucketActions,
            Resource: `arn:aws:s3:::${BUCKET}`,
          },
          {
            Effect: 'Allow',
            Action: ['s3:GetObject', 's3:GetObjectVersion', 's3:PutObject'],
            Resource: `arn:aws:s3:::${BUCKET}/*`,
          },
        ],
      }),
    },
  } as unknown as TerraformResource;
}

function runProject(bucketActions: string[]) {
  const resources = [project(), role(), rolePolicy(bucketActions)];
  const context: TfContext = {
    projectName: 'build-project',
    resource: resources[0],
    allResources: resources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform): S3 artifact bucket permissions on the service role', () => {
  // Primary behavior owned by CODEBUILD-009: GetBucketLocation plus object
  // read/write, but no GetBucketAcl, must be flagged.
  it('flags a project whose role policy grants s3:GetBucketLocation but not s3:GetBucketAcl on the artifact bucket', () => {
    const result = runProject(['s3:GetBucketLocation']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.resourceType).toBe('aws_codebuild_project');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: identical configuration, only the missing action added back.
  it('does not flag the otherwise identical project when s3:GetBucketAcl is also allowed', () => {
    const result = runProject(['s3:GetBucketLocation', 's3:GetBucketAcl']);

    expect(result).toBeNull();
  });
});
