import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-29 (CODEBUILD-009): a CodeBuild project whose artifact bucket name comes from a
 * deployment-time input that analysis cannot resolve must NOT be flagged, even though the
 * service role only allows s3:GetBucketAcl / s3:GetBucketLocation on a fixed, explicitly
 * named bucket -- the unresolved input may resolve to that very bucket.
 */

const FIXED_BUCKET = 'fixed-artifacts-bucket';

const unresolved = (reference: string): string => `__unresolved__:${reference}`;

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: {
    name: 'demo-build-role',
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
          Resource: `arn:aws:s3:::${FIXED_BUCKET}`,
        },
      ],
    }),
  },
};

function project(location: unknown): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: 'aws_iam_role.build',
      source: [{ type: 'NO_SOURCE' }],
      artifacts: [{ type: 'S3', location }],
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

function evaluateProject(location: unknown) {
  const buildProject = project(location);
  const allResources = [buildProject, role, rolePolicy];
  const context: TfContext = {
    projectName: 'test-project',
    resource: buildProject,
    allResources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-29 (Terraform)', () => {
  it('passes when the artifact bucket name is an unresolved deployment-time input', () => {
    // var.artifact_bucket has no reachable default: the bucket name is unknowable.
    expect(evaluateProject(unresolved('var.artifact_bucket'))).toBeNull();
  });

  /**
   * Opposite outcome: the requirement is owned by CODEBUILD-009's core check. With a
   * resolvable artifact bucket name that is NOT the fixed bucket the role covers, the
   * grant is provably insufficient and the project must be flagged.
   */
  it('flags the project when the artifact bucket name resolves to a different named bucket', () => {
    const result = evaluateProject('other-artifacts-bucket');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.issue).toContain('other-artifacts-bucket');
  });
});
