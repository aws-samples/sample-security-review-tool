import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const CACHE_BUCKET = 'my-cache-bucket';

/**
 * REQ-03 (CODEBUILD-009): a project whose only S3 association is its S3 build
 * cache, running under a role defined in the same project that allows both
 * s3:GetBucketAcl and s3:GetBucketLocation on that bucket, passes.
 */
function buildResources(cacheActions: string[]): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'build',
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
      cache: [{ type: 'S3', location: `${CACHE_BUCKET}/cache-prefix` }],
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
    name: 'cache_access',
    address: 'aws_iam_role_policy.cache_access',
    values: {
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: cacheActions,
            Resource: [
              `arn:aws:s3:::${CACHE_BUCKET}`,
              `arn:aws:s3:::${CACHE_BUCKET}/*`,
            ],
          },
        ],
      }),
    },
  } as unknown as TerraformResource;

  return [project, role, rolePolicy];
}

function runOnProject(allResources: TerraformResource[]) {
  const project = allResources.find(resource => resource.type === 'aws_codebuild_project')!;
  const context: TfContext = { projectName: 'test-project', resource: project, allResources };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-03 (Terraform)', () => {
  it('passes when the role policy allows both bucket-inspection actions on the S3 cache bucket', () => {
    const result = runOnProject(buildResources(['s3:GetBucketAcl', 's3:GetBucketLocation']));
    expect(result).toBeNull();
  });

  // Opposite outcome: the pair of permissions is what the requirement turns on.
  it('flags the project when the role policy allows only s3:GetBucketAcl on the same cache bucket', () => {
    const result = runOnProject(buildResources(['s3:GetBucketAcl']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(CACHE_BUCKET);
  });
});
