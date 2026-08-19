import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-build-artifacts';

function buildResources(resourcePattern: string): TerraformResource[] {
  const role: TerraformResource = {
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
  };

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
            Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
            Resource: resourcePattern,
          },
        ],
      }),
    },
  };

  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'app',
    address: 'aws_codebuild_project.app',
    values: {
      name: 'app',
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
  };

  return [role, rolePolicy, project];
}

function runControl(resourcePattern: string) {
  const allResources = buildResources(resourcePattern);
  const project = allResources.find(r => r.type === 'aws_codebuild_project')!;
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform) - wildcard resource pattern covering the bucket itself', () => {
  // Primary behavior owned by CODEBUILD-009.
  it('passes when the policy resource is a prefix wildcard that matches the bucket ARN itself', () => {
    expect(runControl(`arn:aws:s3:::${BUCKET}*`)).toBeNull();
  });

  // Opposite outcome: the wildcard covers only objects inside the bucket.
  it('reports a finding when the wildcard covers only objects within the bucket', () => {
    const result = runControl(`arn:aws:s3:::${BUCKET}/*`);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.app');
    expect(result?.issue).toContain(BUCKET);
  });
});
