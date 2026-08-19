import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';

/**
 * Project stores build artifacts in an S3 bucket and runs under a role declared
 * in the same project, whose only inline policy statement allows `action` on
 * that bucket.
 */
function buildResources(action: string): TerraformResource[] {
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

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'codebuild-service-role' },
  } as unknown as TerraformResource;

  const rolePolicy: TerraformResource = {
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
            Action: action,
            Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
          },
        ],
      }),
    },
  } as unknown as TerraformResource;

  return [project, role, rolePolicy];
}

function runControl(action: string) {
  const allResources = buildResources(action);
  const context: TfContext = {
    projectName: 'test-project',
    resource: allResources[0],
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform) - full-service S3 wildcard on the artifact bucket', () => {
  // Primary behavior owned by CODEBUILD-009: s3:* grants every S3 action,
  // including s3:GetBucketAcl and s3:GetBucketLocation.
  it('passes when the service role policy allows s3:* on the project artifact bucket', () => {
    expect(runControl('s3:*')).toBeNull();
  });

  // Opposite outcome: the same statement, but the allowed action is a real S3
  // action that is neither of the two required bucket-inspection permissions.
  it('flags when the service role policy allows only a non-qualifying S3 action on the artifact bucket', () => {
    const result = runControl('s3:GetObject');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });
});
