import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifacts-bucket';

/**
 * REQ-15 (CODEBUILD-009): the project's artifacts go to an S3 bucket, and the role
 * it runs under — declared in the same project — has one policy document granting
 * s3:GetBucketAcl in one statement and s3:GetBucketLocation in another. IAM unions
 * Allow statements, so the effective permissions satisfy the rule.
 */
function buildResources(secondStatementActions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: BUCKET, name: 'output' }],
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

  const rolePolicy: TerraformResource = {
    type: 'aws_iam_role_policy',
    name: 'build_access',
    address: 'aws_iam_role_policy.build_access',
    values: {
      name: 'build-access',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: ['s3:GetBucketAcl'],
            Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
          },
          {
            Effect: 'Allow',
            Action: secondStatementActions,
            Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
          },
        ],
      }),
    },
  };

  return [project, role, rolePolicy];
}

function evaluateProject(resources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: resources[0],
    allResources: resources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-15 (Terraform)', () => {
  it('passes when the required permissions are split across two statements of one policy document', () => {
    const result = evaluateProject(buildResources(['s3:GetBucketLocation']));
    expect(result).toBeNull();
  });

  // Opposite outcome: the second statement grants a different S3 action, so
  // s3:GetBucketLocation is never allowed on the artifact bucket.
  it('reports a finding when the second statement allows a different action instead of get-bucket-location', () => {
    const result = evaluateProject(buildResources(['s3:GetObject']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain(BUCKET);
  });
});
