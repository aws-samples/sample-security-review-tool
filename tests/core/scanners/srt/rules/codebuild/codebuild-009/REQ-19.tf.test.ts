import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifact-bucket';

/**
 * REQ-19 (CODEBUILD-009): a project whose artifacts live in an S3 bucket passes when its
 * service role, declared in the same project, is allowed an action wildcard that covers
 * both s3:GetBucketAcl and s3:GetBucketLocation on that bucket.
 */
function buildResources(action: string): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: BUCKET, name: 'output' }],
      source: [{ type: 'NO_SOURCE', buildspec: 'version: 0.2' }],
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
    name: 'bucket_inspection',
    address: 'aws_iam_role_policy.bucket_inspection',
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
  };

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

describe('CODEBUILD-009 REQ-19 (Terraform)', () => {
  it('passes when the service role allows the s3:Get* wildcard on the project artifact bucket', () => {
    expect(runControl('s3:Get*')).toBeNull();
  });

  // Opposite outcome: a get-verb wildcard narrowed to object actions covers neither
  // s3:GetBucketAcl nor s3:GetBucketLocation, so the project must be flagged.
  it('flags the project when the wildcard is narrowed to s3:GetObject* and covers neither required action', () => {
    const result = runControl('s3:GetObject*');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain(BUCKET);
  });
});
