import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (CODEBUILD-009): the rule only requires s3:GetBucketAcl and
 * s3:GetBucketLocation for S3 buckets the project actually associates.
 * A git-provider source, NO_ARTIFACTS output, no cache block (service default
 * NO_CACHE) and CloudWatch-only logs associate no bucket, so a role policy
 * granting neither action is compliant.
 */

const factory = new Codebuild009TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: { name: 'git-sourced-project-role' },
};

// Inline role policy that deliberately grants neither required action.
const rolePolicy: TerraformResource = {
  type: 'aws_iam_role_policy',
  name: 'build',
  address: 'aws_iam_role_policy.build',
  values: {
    role: 'aws_iam_role.build',
    policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['logs:CreateLogStream', 'logs:PutLogEvents', 's3:GetObject'],
          Resource: '*',
        },
      ],
    }),
  },
};

function project(overrides: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'git_sourced',
    address: 'aws_codebuild_project.git_sourced',
    values: {
      name: 'git-sourced-project',
      service_role: 'aws_iam_role.build',
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
      source: [{ type: 'GITHUB', location: 'https://github.com/example-org/example-repo.git' }],
      artifacts: [{ type: 'NO_ARTIFACTS' }],
      logs_config: [
        {
          cloudwatch_logs: [{ status: 'ENABLED', group_name: '/aws/codebuild/git-sourced-project' }],
        },
      ],
      ...overrides,
    },
  };
}

function contextFor(projectResource: TerraformResource): TfContext {
  return {
    projectName: 'test-project',
    resource: projectResource,
    allResources: [projectResource, role, rolePolicy],
  };
}

describe('CODEBUILD-009 REQ-07 (Terraform)', () => {
  it('passes when the project associates no S3 bucket and the role grants neither required action', () => {
    const context = contextFor(project({}));
    const adapter = factory.bind(context) as any;

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: identical project and permission-less role, except the
  // build output now lands in an S3 bucket, so a bucket IS associated.
  it('flags the otherwise identical project once an S3 artifact bucket is associated', () => {
    const context = contextFor(
      project({ artifacts: [{ type: 'S3', location: 'build-output-bucket' }] }),
    );
    const adapter = factory.bind(context) as any;

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual(['build-output-bucket']);

    const result = codebuild009Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.git_sourced');
  });
});
