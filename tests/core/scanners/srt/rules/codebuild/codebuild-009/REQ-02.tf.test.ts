import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET_ARN = 'arn:aws:s3:::my-source-bucket';

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'demo',
  address: 'aws_codebuild_project.demo',
  values: {
    name: 'demo-project',
    service_role: 'aws_iam_role.build',
    source: [{ type: 'S3', location: 'my-source-bucket/source.zip' }],
    artifacts: [{ type: 'NO_ARTIFACTS' }],
    environment: [
      {
        compute_type: 'BUILD_GENERAL1_SMALL',
        image: 'aws/codebuild/standard:7.0',
        type: 'LINUX_CONTAINER',
      },
    ],
  },
} as unknown as TerraformResource;

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: { name: 'demo-build-role' },
} as unknown as TerraformResource;

function rolePolicy(actions: string[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'source_access',
    address: 'aws_iam_role_policy.source_access',
    values: {
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: actions,
            Resource: BUCKET_ARN,
          },
        ],
      }),
    },
  } as unknown as TerraformResource;
}

function runOnProject(policy: TerraformResource) {
  const allResources = [project, role, policy];
  const factory = new Codebuild009TfAdapterFactory();
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

describe('CODEBUILD-009 Terraform - S3 source bucket with NO_ARTIFACTS output', () => {
  // Primary behavior owned by CODEBUILD-009: role grants both required bucket-inspection permissions.
  it('passes when the role policy allows both s3:GetBucketAcl and s3:GetBucketLocation on the S3 source bucket', () => {
    const result = runOnProject(rolePolicy(['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:GetObject']));
    expect(result).toBeNull();
  });

  // Opposite outcome: identical configuration except one required action is absent from the allow statement.
  it('flags the project when the role policy allows only s3:GetBucketLocation on the S3 source bucket', () => {
    const result = runOnProject(rolePolicy(['s3:GetBucketLocation', 's3:GetObject']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain('my-source-bucket');
  });
});
