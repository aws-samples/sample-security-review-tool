import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009TfAdapterFactory();

/**
 * REQ-24 (CODEBUILD-009): the project's service role must effectively allow
 * both s3:GetBucketAcl and s3:GetBucketLocation on every S3 bucket the project
 * uses. Here the grants are scoped exclusively to an unrelated bucket ARN.
 */
function buildResources(grantedBucketArn: string): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      artifacts: [{ type: 'S3', location: 'artifact-bucket', name: 'output.zip' }],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    },
  } as unknown as TerraformResource;

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: { name: 'demo-build-role' },
  } as unknown as TerraformResource;

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
            Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
            Resource: grantedBucketArn,
          },
        ],
      }),
    },
  } as unknown as TerraformResource;

  return [project, role, rolePolicy];
}

function runOn(allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: allResources[0],
    allResources,
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 REQ-24 (Terraform)', () => {
  it('flags a project whose role grants the bucket-inspection actions only on an unrelated bucket', () => {
    const result = runOn(buildResources('arn:aws:s3:::unrelated-bucket'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain('artifact-bucket');
  });

  // Opposite outcome: the nearest input that flips the verdict is the same
  // grant scoped to the project's actual artifact bucket instead.
  it('does not flag when the same grants are scoped to the project artifact bucket', () => {
    const result = runOn(buildResources('arn:aws:s3:::artifact-bucket'));

    expect(result).toBeNull();
  });
});
