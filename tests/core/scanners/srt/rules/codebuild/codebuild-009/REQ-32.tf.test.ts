import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ARTIFACTS_BUCKET = 'artifacts-bucket';
const CACHE_BUCKET = 'cache-bucket';

const REQUIRED_ACTIONS = ['s3:GetBucketAcl', 's3:GetBucketLocation'];

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'demo',
  address: 'aws_codebuild_project.demo',
  values: {
    name: 'demo-project',
    service_role: 'aws_iam_role.build',
    artifacts: [{ type: 'S3', location: ARTIFACTS_BUCKET }],
    cache: [{ type: 'S3', location: CACHE_BUCKET }],
    source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    environment: [
      {
        type: 'LINUX_CONTAINER',
        compute_type: 'BUILD_GENERAL1_SMALL',
        image: 'aws/codebuild/standard:7.0',
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

function rolePolicy(bucketArns: string[]): TerraformResource {
  return {
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
            Action: REQUIRED_ACTIONS,
            Resource: bucketArns,
          },
        ],
      }),
    },
  };
}

function evaluateProject(bucketArns: string[]): ScanResult | null {
  const allResources = [project, role, rolePolicy(bucketArns)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform): required bucket-inspection permissions must cover every associated bucket', () => {
  it('flags the project when the permissions are scoped only to the artifacts bucket, leaving the S3 cache bucket uncovered', () => {
    const result = evaluateProject([`arn:aws:s3:::${ARTIFACTS_BUCKET}`]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain(CACHE_BUCKET);
  });

  // Opposite outcome: identical configuration except the same allow statement
  // also covers the cache bucket, so no associated bucket is uncovered.
  it('does not flag the project when the same permissions cover both the artifacts bucket and the cache bucket', () => {
    const result = evaluateProject([
      `arn:aws:s3:::${ARTIFACTS_BUCKET}`,
      `arn:aws:s3:::${CACHE_BUCKET}`,
    ]);

    expect(result).toBeNull();
  });
});
