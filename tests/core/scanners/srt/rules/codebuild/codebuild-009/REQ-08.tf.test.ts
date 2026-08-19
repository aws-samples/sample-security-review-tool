import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (CODEBUILD-009): A project whose only S3 association is an S3 build-log
 * destination with status DISABLED has no S3 bucket association, so the service
 * role does not need s3:GetBucketAcl / s3:GetBucketLocation.
 */

const factory = new Codebuild009TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'project',
  address: 'aws_iam_role.project',
  values: { name: 'build-project-role' },
} as TerraformResource;

// Policy that grants neither get-bucket-ACL nor get-bucket-location.
const rolePolicy: TerraformResource = {
  type: 'aws_iam_role_policy',
  name: 'build',
  address: 'aws_iam_role_policy.build',
  values: {
    role: 'aws_iam_role.project',
    policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['s3:PutObject', 's3:GetObject'],
          Resource: 'arn:aws:s3:::build-logs-bucket/*',
        },
      ],
    }),
  },
} as TerraformResource;

function project(s3LogsStatus: string): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'app',
    address: 'aws_codebuild_project.app',
    values: {
      name: 'app',
      service_role: 'aws_iam_role.project',
      artifacts: [{ type: 'NO_ARTIFACTS' }],
      source: [{ type: 'CODECOMMIT', location: 'https://git-codecommit.us-east-1.amazonaws.com/v1/repos/app' }],
      environment: [
        { compute_type: 'BUILD_GENERAL1_SMALL', image: 'aws/codebuild/standard:7.0', type: 'LINUX_CONTAINER' },
      ],
      logs_config: [
        {
          s3_logs: [{ status: s3LogsStatus, location: 'build-logs-bucket/logs' }],
        },
      ],
    },
  } as TerraformResource;
}

function contextFor(s3LogsStatus: string): TfContext {
  const projectResource = project(s3LogsStatus);
  return {
    projectName: 'test-project',
    resource: projectResource,
    allResources: [projectResource, role, rolePolicy],
  };
}

describe('CODEBUILD-009 REQ-08 (Terraform)', () => {
  it('passes when the S3 logs destination is DISABLED and the role grants neither bucket-inspection permission', () => {
    const context = contextFor('DISABLED');
    const adapter = factory.bind(context);

    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: primary behaviour owned by the base CODEBUILD-009 requirement.
  it('flags the same project when the S3 logs destination is ENABLED', () => {
    const context = contextFor('ENABLED');
    const adapter = factory.bind(context);

    const result = codebuild009Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.issue).toContain('build-logs-bucket');
  });
});
