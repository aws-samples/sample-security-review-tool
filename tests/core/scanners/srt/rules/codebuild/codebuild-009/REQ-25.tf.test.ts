import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-25 (CODEBUILD-009): a project whose artifacts live in an S3 bucket passes when the
 * service role declared in the same project allows both s3:GetBucketAcl and
 * s3:GetBucketLocation on Resource "*", because a wildcard resource matches every bucket ARN.
 */

const ARTIFACT_BUCKET = 'my-artifact-bucket';

function policyJson(actions: string[]): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: actions,
        Resource: '*',
      },
    ],
  });
}

function buildResources(actions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'my-build',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: ARTIFACT_BUCKET }],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    },
  } as TerraformResource;

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'build-role' },
  } as TerraformResource;

  const rolePolicy: TerraformResource = {
    type: 'aws_iam_role_policy',
    name: 'build_access',
    address: 'aws_iam_role_policy.build_access',
    values: {
      name: 'build-access',
      role: 'aws_iam_role.build',
      policy: policyJson(actions),
    },
  } as TerraformResource;

  return [project, role, rolePolicy];
}

function runControl(resources: TerraformResource[]): ScanResult | null {
  const context: TfContext = {
    projectName: 'test-project',
    resource: resources[0],
    allResources: resources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-25 (Terraform)', () => {
  it('passes when the service role policy allows both bucket-inspection actions on Resource "*"', () => {
    expect(runControl(buildResources(['s3:GetBucketAcl', 's3:GetBucketLocation']))).toBeNull();
  });

  // Opposite outcome: the wildcard resource is unchanged, but one required action is absent,
  // so the requirement is no longer satisfied for the artifact bucket.
  it('flags the project when the wildcard statement omits s3:GetBucketAcl', () => {
    const result = runControl(buildResources(['s3:GetBucketLocation']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(ARTIFACT_BUCKET);
  });
});
