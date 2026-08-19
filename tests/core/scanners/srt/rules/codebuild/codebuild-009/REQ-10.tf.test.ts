import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009TfAdapterFactory();

function scan(resource: TerraformResource, allResources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

const EXTERNAL_ROLE_ARN = 'arn:aws:iam::123456789012:role/preexisting-codebuild-role';

function project(serviceRole: string): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'artifact_writer',
    address: 'aws_codebuild_project.artifact_writer',
    values: {
      name: 'artifact-writer',
      service_role: serviceRole,
      artifacts: [{ type: 'S3', location: 'my-artifact-bucket' }],
      source: [{ type: 'NO_SOURCE' }],
      environment: [
        {
          compute_type: 'BUILD_GENERAL1_SMALL',
          image: 'aws/codebuild/standard:7.0',
          type: 'LINUX_CONTAINER',
        },
      ],
    },
  } as unknown as TerraformResource;
}

/**
 * REQ-10 (primary): a project that writes artifacts to an S3 bucket while running
 * under a role identified only by an identifier that is not declared anywhere in the
 * project must be flagged - no policy in the project grants s3:GetBucketAcl or
 * s3:GetBucketLocation on that bucket.
 */
describe('CODEBUILD-009 REQ-10 (Terraform)', () => {
  it('flags a project with S3 artifacts whose service role is not declared in the project', () => {
    const target = project(EXTERNAL_ROLE_ARN);

    const result = scan(target, [target]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.artifact_writer');
    expect(result?.issue).toContain('my-artifact-bucket');
  });

  // Opposite outcome: identical project, except the service role IS declared in the
  // project and an inline role policy allows both required actions on the same bucket.
  it('does not flag when the service role is declared in the project and grants both required permissions', () => {
    const target = project('aws_iam_role.build');

    const role: TerraformResource = {
      type: 'aws_iam_role',
      name: 'build',
      address: 'aws_iam_role.build',
      values: { name: 'codebuild-service-role' },
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
              Resource: [
                'arn:aws:s3:::my-artifact-bucket',
                'arn:aws:s3:::my-artifact-bucket/*',
              ],
            },
          ],
        }),
      },
    } as unknown as TerraformResource;

    expect(scan(target, [target, role, rolePolicy])).toBeNull();
  });
});
