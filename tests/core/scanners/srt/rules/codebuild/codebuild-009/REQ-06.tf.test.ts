import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'secondary-source-bucket';

function policyJson(actions: string[]): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: actions,
        Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
      },
    ],
  });
}

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: { name: 'demo-build-role' },
} as TerraformResource;

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'demo',
  address: 'aws_codebuild_project.demo',
  values: {
    name: 'demo-project',
    service_role: 'aws_iam_role.build',
    artifacts: [{ type: 'NO_ARTIFACTS' }],
    environment: [
      { type: 'LINUX_CONTAINER', compute_type: 'BUILD_GENERAL1_SMALL', image: 'aws/codebuild/standard:7.0' },
    ],
    source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    secondary_sources: [
      { type: 'S3', location: `${BUCKET}/inputs/source.zip`, source_identifier: 'extra' },
    ],
  },
} as TerraformResource;

function rolePolicy(actions: string[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'bucket_inspection',
    address: 'aws_iam_role_policy.bucket_inspection',
    values: {
      name: 'bucket-inspection',
      role: 'aws_iam_role.build',
      policy: policyJson(actions),
    },
  } as TerraformResource;
}

function run(actions: string[]) {
  const allResources = [project, role, rolePolicy(actions)];
  const context: TfContext = {
    projectName: 'codebuild-009-project',
    resource: project,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform) - secondary S3 source bucket covered by in-project role policy', () => {
  // Primary behaviour owned by CODEBUILD-009: both required actions present -> no finding.
  it('passes when the role policy allows both s3:GetBucketAcl and s3:GetBucketLocation on the secondary source bucket', () => {
    expect(run(['s3:GetBucketAcl', 's3:GetBucketLocation'])).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict - one of the required pair is absent.
  it('flags the project when the same policy allows only s3:GetBucketLocation on that bucket', () => {
    const result = run(['s3:GetBucketLocation']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain(BUCKET);
  });
});
