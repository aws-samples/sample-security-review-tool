import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';
const AWS_MANAGED_POLICY_ARN = 'arn:aws:iam::aws:policy/AWSCodeBuildDeveloperAccess';

const factory = new Codebuild009TfAdapterFactory();

const projectResource: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'build',
  address: 'aws_codebuild_project.build',
  values: {
    name: 'build-project',
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
} as TerraformResource;

const roleResource: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: {
    name: 'build-role',
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
} as TerraformResource;

// Only permission source: an attachment to an AWS-provided managed policy whose
// contents are not part of the project.
const managedPolicyAttachment: TerraformResource = {
  type: 'aws_iam_role_policy_attachment',
  name: 'managed',
  address: 'aws_iam_role_policy_attachment.managed',
  values: {
    role: 'aws_iam_role.build',
    policy_arn: AWS_MANAGED_POLICY_ARN,
  },
} as TerraformResource;

function run(allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: projectResource,
    allResources,
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 (Terraform): service role permissions for associated S3 buckets', () => {
  // Primary behaviour owned by this requirement.
  it('flags a project whose service role only carries a service-provided managed policy', () => {
    const result = run([projectResource, roleResource, managedPolicyAttachment]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: identical project and role, plus an in-project policy that
  // explicitly allows both required actions on the artifact bucket.
  it('does not flag when the same role explicitly allows both bucket-inspection actions', () => {
    const inlinePolicy: TerraformResource = {
      type: 'aws_iam_role_policy',
      name: 'inspection',
      address: 'aws_iam_role_policy.inspection',
      values: {
        role: 'aws_iam_role.build',
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
              Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
            },
            {
              Effect: 'Allow',
              Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
              Resource: '*',
            },
          ],
        }),
      },
    } as TerraformResource;

    expect(run([projectResource, roleResource, managedPolicyAttachment, inlinePolicy])).toBeNull();
  });
});
