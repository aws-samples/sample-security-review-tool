import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009TfAdapterFactory();

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'build',
  address: 'aws_codebuild_project.build',
  values: {
    name: 'build',
    service_role: 'aws_iam_role.build',
    artifacts: [{ type: 'S3', location: 'my-artifact-bucket' }],
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

function rolePolicy(statement: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'build',
    address: 'aws_iam_role_policy.build',
    values: {
      name: 'build-policy',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({ Version: '2012-10-17', Statement: [statement] }),
    },
  };
}

function bind(allResources: TerraformResource[]): { adapter: Codebuild009Adapter; context: TfContext } {
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  return { adapter: factory.bind(context) as Codebuild009Adapter, context };
}

describe('CODEBUILD-009 (Terraform) - wildcard admin policy satisfies bucket inspection permissions', () => {
  it('does not flag a project whose in-project service role allows every action on every resource', () => {
    const { adapter, context } = bind([
      project,
      role,
      rolePolicy({ Effect: 'Allow', Action: '*', Resource: '*' }),
    ]);

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the statement is
  // still present and still allows an S3 bucket-inspection action, but it omits
  // s3:GetBucketLocation, so the required permission set is incomplete.
  it('flags the same project when the policy allows only one of the two required actions', () => {
    const { adapter, context } = bind([
      project,
      role,
      rolePolicy({ Effect: 'Allow', Action: ['s3:GetBucketAcl'], Resource: '*' }),
    ]);

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual(['my-artifact-bucket']);
    const result = codebuild009Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
  });
});
