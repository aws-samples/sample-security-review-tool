import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (CODEBUILD-009): CodeBuild project service roles must include both
 * s3:GetBucketAcl and s3:GetBucketLocation for any S3 bucket associated with
 * the project.
 *
 * Scenario under test: source and artifacts are both of type CODEPIPELINE, so
 * the project reads/writes the pipeline's S3 artifact bucket under its service
 * role. The role is declared in the same project and its inline policy grants
 * neither required permission -> expect a finding.
 */

const factory = new Codebuild009TfAdapterFactory();

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'pipeline',
  address: 'aws_codebuild_project.pipeline',
  values: {
    name: 'pipeline-project',
    service_role: 'aws_iam_role.build',
    artifacts: [{ type: 'CODEPIPELINE' }],
    source: [{ type: 'CODEPIPELINE' }],
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
  values: { name: 'pipeline-build-role' },
} as unknown as TerraformResource;

function rolePolicy(actions: string[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'build',
    address: 'aws_iam_role_policy.build',
    values: {
      name: 'build-policy',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: actions, Resource: '*' }],
      }),
    },
  } as unknown as TerraformResource;
}

function contextFor(policyActions: string[]): TfContext {
  const allResources = [project, role, rolePolicy(policyActions)];
  return { projectName: 'pipeline-project', resource: project, allResources };
}

describe('CODEBUILD-009 (Terraform) - CODEPIPELINE-managed source and artifacts', () => {
  it('flags a CODEPIPELINE project whose in-project role policy grants neither get-bucket-ACL nor get-bucket-location', () => {
    const context = contextFor(['s3:PutObject', 's3:GetObject']);
    const adapter = factory.bind(context);

    const result = codebuild009Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.pipeline');
    expect(result?.resourceType).toBe('aws_codebuild_project');
  });

  // Opposite outcome: nearest input that flips the verdict - identical project
  // and role, but the inline policy now grants both permissions.
  it('does not flag the same CODEPIPELINE project when the role policy grants both permissions', () => {
    const context = contextFor([
      's3:PutObject',
      's3:GetObject',
      's3:GetBucketAcl',
      's3:GetBucketLocation',
    ]);
    const adapter = factory.bind(context);

    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });
});
