import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const SECONDARY_BUCKET = 'my-secondary-artifact-bucket';

function project(): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'build',
      service_role: 'aws_iam_role.build',
      // No primary build output.
      artifacts: [{ type: 'NO_ARTIFACTS' }],
      // The only associated S3 bucket: the additional output artifact.
      secondary_artifacts: [
        { artifact_identifier: 'extra', type: 'S3', location: SECONDARY_BUCKET },
      ],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    },
  } as TerraformResource;
}

function role(): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'codebuild-service-role' },
  } as TerraformResource;
}

function rolePolicy(actions: string[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: actions,
            Resource: `arn:aws:s3:::${SECONDARY_BUCKET}`,
          },
        ],
      }),
    },
  } as TerraformResource;
}

function run(actions: string[]) {
  const target = project();
  const allResources = [target, role(), rolePolicy(actions)];
  const context: TfContext = { projectName: 'tf-project', resource: target, allResources };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 Terraform - secondary S3 artifact bucket with fully permitted in-project service role', () => {
  // Primary behavior owned by CODEBUILD-009: both bucket-inspection permissions granted -> compliant.
  it('passes when the role policy allows both s3:GetBucketAcl and s3:GetBucketLocation on the secondary artifact bucket', () => {
    const result = run(['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:PutObject']);

    expect(result).toBeNull();
  });

  it('flags the project when the same role policy grants only s3:GetBucketLocation on that bucket (opposite case)', () => {
    const result = run(['s3:GetBucketLocation', 's3:PutObject']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(SECONDARY_BUCKET);
  });
});
