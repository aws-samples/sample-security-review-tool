import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-output-bucket';

/**
 * REQ-13 (CODEBUILD-009 owns this behavior):
 * A project storing artifacts in an S3 bucket whose service role, declared in the
 * same project, only grants object-level read/write on that bucket must be flagged.
 */
const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'build',
  address: 'aws_codebuild_project.build',
  values: {
    name: 'build-project',
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
};

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: {
    name: 'build-project-role',
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

const OBJECT_ONLY_STATEMENT = {
  Effect: 'Allow',
  Action: ['s3:GetObject', 's3:GetObjectVersion', 's3:PutObject'],
  Resource: `arn:aws:s3:::${BUCKET}/*`,
};

const BUCKET_LEVEL_STATEMENT = {
  Effect: 'Allow',
  Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
  Resource: `arn:aws:s3:::${BUCKET}`,
};

function rolePolicy(statements: unknown[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      name: 'artifact-access',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
    },
  };
}

function run(statements: unknown[]) {
  const allResources = [project, role, rolePolicy(statements)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-13 (Terraform)', () => {
  it('flags a project whose service role grants only object-level permissions on the artifact bucket', () => {
    const result = run([OBJECT_ONLY_STATEMENT]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });

  it('does not flag the same project when the role additionally grants the bucket-level inspection actions', () => {
    // Opposite outcome: only the presence of s3:GetBucketAcl / s3:GetBucketLocation changes.
    const result = run([OBJECT_ONLY_STATEMENT, BUCKET_LEVEL_STATEMENT]);

    expect(result).toBeNull();
  });
});
