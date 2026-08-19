import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009TfAdapterFactory();

function policyJson(actions: string[]): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: actions,
        Resource: ['arn:aws:s3:::log-bucket', 'arn:aws:s3:::log-bucket/*'],
      },
    ],
  });
}

// Project's only S3 association is its build-log bucket; role is in the same project.
function buildResources(roleActions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'NO_ARTIFACTS' }],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
      logs_config: [
        {
          s3_logs: [{ status: 'ENABLED', location: 'log-bucket/build-logs' }],
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
    name: 'log_bucket_access',
    address: 'aws_iam_role_policy.log_bucket_access',
    values: {
      name: 'log-bucket-access',
      role: 'aws_iam_role.build',
      policy: policyJson(roleActions),
    },
  } as unknown as TerraformResource;

  return [project, role, rolePolicy];
}

function run(resources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: resources[0],
    allResources: resources,
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 Terraform - REQ-04', () => {
  // Primary behavior owned by this requirement: both permissions granted on the
  // only associated bucket (the build-log bucket) => compliant.
  it('passes when the service role policy allows both get-bucket-ACL and get-bucket-location on the log bucket', () => {
    const result = run(buildResources(['s3:PutObject', 's3:GetBucketAcl', 's3:GetBucketLocation']));
    expect(result).toBeNull();
  });

  // Opposite outcome: same configuration, one required permission missing.
  it('flags the project when the role policy allows get-bucket-ACL but not get-bucket-location', () => {
    const result = run(buildResources(['s3:PutObject', 's3:GetBucketAcl']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain('log-bucket');
  });
});
