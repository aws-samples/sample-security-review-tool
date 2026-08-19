import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ARTIFACT_BUCKET = 'artifact-bucket';
const ROLE_NAME = 'codebuild-service-role';

function project(): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'my-project',
      // Literal role identifier naming the in-project role.
      service_role: ROLE_NAME,
      artifacts: [{ type: 'S3', location: ARTIFACT_BUCKET, name: 'build-output.zip' }],
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
}

function role(): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'codebuild',
    address: 'aws_iam_role.codebuild',
    values: { name: ROLE_NAME },
  };
}

function rolePolicy(actions: string[]): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      name: 'artifact-access',
      role: ROLE_NAME,
      policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: actions,
            Resource: [
              `arn:aws:s3:::${ARTIFACT_BUCKET}`,
              `arn:aws:s3:::${ARTIFACT_BUCKET}/*`,
            ],
          },
        ],
      }),
    },
  };
}

function run(actions: string[]) {
  const allResources = [project(), role(), rolePolicy(actions)];
  const context: TfContext = {
    projectName: 'test-project',
    resource: allResources[0],
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform) - service role bucket inspection permissions', () => {
  // Primary behaviour owned by this requirement.
  it('passes when the literally named in-project role allows both s3:GetBucketAcl and s3:GetBucketLocation on the artifact bucket', () => {
    const result = run(['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:PutObject']);

    expect(result).toBeNull();
  });

  // Opposite outcome: same wiring, but only one of the required pair is allowed.
  it('flags the project when the same role allows s3:GetBucketAcl but not s3:GetBucketLocation', () => {
    const result = run(['s3:GetBucketAcl', 's3:PutObject']);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(ARTIFACT_BUCKET);
  });
});
