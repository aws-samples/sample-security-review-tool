import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';

function resources(actions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'build',
      // service_role = aws_iam_role.build.arn collapses to the role address
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: BUCKET }],
      source: [{ type: 'NO_SOURCE' }],
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
    },
  } as TerraformResource;

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'build-role' },
  } as TerraformResource;

  const policy: TerraformResource = {
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
            Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
          },
        ],
      }),
    },
  } as TerraformResource;

  return [project, role, policy];
}

function bindProject(all: TerraformResource[]): { adapter: Codebuild009Adapter; context: TfContext } {
  const context: TfContext = {
    projectName: 'test-project',
    resource: all[0],
    allResources: all,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return { adapter, context };
}

describe('CODEBUILD-009 (Terraform) - lower-cased action names still grant the required permissions', () => {
  // Primary behaviour owned by this requirement: IAM action matching is case insensitive.
  it('does not flag a project whose role policy allows s3:getbucketacl and s3:getbucketlocation in lower case on the artifact bucket', () => {
    const { adapter, context } = bindProject(
      resources(['s3:getbucketacl', 's3:getbucketlocation']),
    );

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: lower-cased action names that are not the required permissions must still be flagged.
  it('flags a project whose role policy allows lower-cased actions other than the two required bucket-inspection actions', () => {
    const { adapter, context } = bindProject(resources(['s3:getobject', 's3:putobject']));

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([BUCKET]);
    const result = codebuild009Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
  });
});
