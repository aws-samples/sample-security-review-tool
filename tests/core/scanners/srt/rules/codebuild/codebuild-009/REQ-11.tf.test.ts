import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifacts-bucket';

/**
 * REQ-11 (CODEBUILD-009): a project that stores artifacts in an S3 bucket must run
 * under a service role that allows BOTH s3:GetBucketAcl and s3:GetBucketLocation.
 */
function buildResources(bucketActions: string[]): TerraformResource[] {
  const project: TerraformResource = {
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
  };

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'build',
    address: 'aws_iam_role.build',
    values: {
      name: 'build-service-role',
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
      name: 'artifact-access',
      role: 'aws_iam_role.build',
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: bucketActions,
            Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
          },
        ],
      }),
    },
  };

  return [project, role, rolePolicy];
}

function evaluateProject(resources: TerraformResource[]) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: resources[0],
    allResources: resources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-11 (Terraform)', () => {
  it('flags a project whose role policy allows get-bucket-ACL and object read/write but omits get-bucket-location', () => {
    const result = evaluateProject(
      buildResources(['s3:GetBucketAcl', 's3:GetObject', 's3:GetObjectVersion', 's3:PutObject']),
    );

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CODEBUILD-009');
    expect(result!.resourceName).toBe('aws_codebuild_project.build');
    expect(result!.issue).toContain(BUCKET);
  });

  // Opposite outcome: the only change is that the missing permission is present.
  it('does not flag the same project when the role policy also allows get-bucket-location', () => {
    const result = evaluateProject(
      buildResources([
        's3:GetBucketAcl',
        's3:GetBucketLocation',
        's3:GetObject',
        's3:GetObjectVersion',
        's3:PutObject',
      ]),
    );

    expect(result).toBeNull();
  });
});
