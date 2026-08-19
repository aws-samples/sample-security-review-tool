import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifact-bucket';
const factory = new Codebuild009TfAdapterFactory();

const project: TerraformResource = {
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
};

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: { name: 'demo-build-role' },
};

/** The role's inline policy, carrying the given statement list. */
function rolePolicy(statements: unknown[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'build',
    address: 'aws_iam_role_policy.build',
    values: {
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
  const adapter = factory.bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform): S3 artifact bucket with an empty in-project role policy', () => {
  // Primary behavior owned by CODEBUILD-009: an empty statement list grants
  // nothing, so neither s3:GetBucketAcl nor s3:GetBucketLocation is held.
  it('flags a project whose service role policy document has no statements', () => {
    const result = run([]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.resourceType).toBe('aws_codebuild_project');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: the nearest input that flips the verdict — the same role
  // policy document, still present, but now granting both required actions.
  it('does not flag a project whose service role policy grants both required actions on the bucket', () => {
    const result = run([
      {
        Effect: 'Allow',
        Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
        Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
      },
    ]);

    expect(result).toBeNull();
  });
});
