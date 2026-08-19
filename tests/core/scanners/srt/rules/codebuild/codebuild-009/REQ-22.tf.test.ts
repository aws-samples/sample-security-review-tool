import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';

function project(): TerraformResource {
  return {
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
  } as TerraformResource;
}

function role(): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'build-role' },
  } as TerraformResource;
}

function rolePolicy(effect: 'Allow' | 'Deny'): TerraformResource {
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
            Effect: effect,
            Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
            Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
          },
        ],
      }),
    },
  } as TerraformResource;
}

function bindProject(effect: 'Allow' | 'Deny'): { adapter: Codebuild009Adapter; context: TfContext } {
  const projectResource = project();
  const allResources = [projectResource, role(), rolePolicy(effect)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: projectResource,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return { adapter, context };
}

describe('CODEBUILD-009 (Terraform) - artifact bucket permissions granted with a denying effect', () => {
  // Primary behaviour owned by CODEBUILD-009: a Deny statement grants nothing.
  it('flags a project whose service role policy denies both required bucket actions on the artifact bucket', () => {
    const { adapter, context } = bindProject('Deny');

    const result = codebuild009Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(adapter.bucketsMissingRequiredPermissions()).toContain(BUCKET);
  });

  // Opposite outcome: identical fixture, only the statement effect flips to Allow.
  it('does not flag the same project when the statement effect allows both required bucket actions', () => {
    const { adapter, context } = bindProject('Allow');

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });
});
