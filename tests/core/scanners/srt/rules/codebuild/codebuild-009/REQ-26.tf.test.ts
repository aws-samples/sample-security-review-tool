import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifacts-bucket';
const factory = new Codebuild009TfAdapterFactory();

function buildResources(policyResources: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'build',
      service_role: 'aws_iam_role.project',
      artifacts: [{ type: 'S3', location: BUCKET }],
      source: [{ type: 'NO_SOURCE' }],
    },
  };

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'project',
    address: 'aws_iam_role.project',
    values: { name: 'project-role' },
  };

  const rolePolicy: TerraformResource = {
    type: 'aws_iam_role_policy',
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      role: 'aws_iam_role.project',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
            Resource: policyResources,
          },
        ],
      }),
    },
  };

  return [project, role, rolePolicy];
}

function run(allResources: TerraformResource[]): ScanResult | null {
  const project = allResources.find(resource => resource.type === 'aws_codebuild_project')!;
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

describe('CODEBUILD-009 (Terraform) — bucket-level permissions scoped only to objects', () => {
  // Primary behaviour owned by CODEBUILD-009.
  it('flags a project whose role allows both actions only on objects inside the artifact bucket', () => {
    const result = run(buildResources([`arn:aws:s3:::${BUCKET}/*`]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: same grant, but the resource is the bucket ARN itself.
  it('does not flag when the same two actions are scoped to the bucket ARN itself', () => {
    const result = run(buildResources([`arn:aws:s3:::${BUCKET}`]));

    expect(result).toBeNull();
  });
});
