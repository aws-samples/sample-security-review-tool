import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-output-bucket';

const factory = new Codebuild009TfAdapterFactory();

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'build',
  address: 'aws_codebuild_project.build',
  values: {
    name: 'build',
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
} as unknown as TerraformResource;

const trustOnlyRole: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: {
    name: 'build-service-role',
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
} as unknown as TerraformResource;

const bucketInspectionPolicy: TerraformResource = {
  type: 'aws_iam_role_policy',
  name: 'inspection',
  address: 'aws_iam_role_policy.inspection',
  values: {
    role: 'aws_iam_role.build',
    policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
          Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
        },
      ],
    }),
  },
} as unknown as TerraformResource;

function run(allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 (Terraform): service role must grant s3:GetBucketAcl and s3:GetBucketLocation on associated buckets', () => {
  // Primary behavior owned by CODEBUILD-009: trust policy only, no attached or inline permission policies.
  it('flags a project whose S3 artifact bucket is used by a role that has only a trust policy', () => {
    const result = run([project, trustOnlyRole]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: identical project and role, plus an inline role policy granting both required actions.
  it('does not flag when the same role has an inline policy allowing both required actions', () => {
    const result = run([project, trustOnlyRole, bucketInspectionPolicy]);

    expect(result).toBeNull();
  });
});
