import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-28 (CODEBUILD-009): CodeBuild project service roles must include both
 * s3:GetBucketAcl and s3:GetBucketLocation for any S3 bucket associated with
 * the project.
 *
 * Scenario under test: the project writes artifacts to an S3 bucket and its
 * service role is declared in the same project, but the role policy document
 * is supplied by a variable with no reachable default, so the allowed-actions
 * list is unknown at analysis time. The rule must not assert a breach.
 */

const ARTIFACT_BUCKET = 'build-artifacts-bucket';

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

const project: TerraformResource = {
  type: 'aws_codebuild_project',
  name: 'build',
  address: 'aws_codebuild_project.build',
  values: {
    name: 'build',
    service_role: 'aws_iam_role.build',
    artifacts: [{ type: 'S3', location: ARTIFACT_BUCKET }],
    source: [{ type: 'NO_SOURCE' }],
  },
};

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'build',
  address: 'aws_iam_role.build',
  values: {
    name: 'codebuild-service-role',
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

function rolePolicy(policy: unknown): TerraformResource {
  return {
    type: 'aws_iam_role_policy',
    name: 'artifact_access',
    address: 'aws_iam_role_policy.artifact_access',
    values: {
      name: 'artifact-access',
      role: 'aws_iam_role.build',
      policy,
    },
  };
}

function policyJson(actions: string[]): string {
  return JSON.stringify({
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
  });
}

function runControl(policyResource: TerraformResource) {
  const allResources = [project, role, policyResource];
  const factory = new Codebuild009TfAdapterFactory();
  const context: TfContext = {
    projectName: 'test-project',
    resource: project,
    allResources,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

describe('CODEBUILD-009 (Terraform) - REQ-28', () => {
  it('passes when the role policy document comes from an unresolvable deployment-time input', () => {
    // policy = var.artifact_policy_json, no declared default -> unknown
    expect(runControl(rolePolicy(unresolved('var.artifact_policy_json')))).toBeNull();
  });

  // Opposite outcome: identical fixture, but the policy document is a known
  // literal whose action list omits the required bucket-inspection actions.
  // That behaviour is owned by CODEBUILD-009's primary requirement; it is
  // included here so this file cannot pass with a control that never flags.
  it('flags when the same role policy lists known actions that omit the required permissions', () => {
    const result = runControl(rolePolicy(policyJson(['s3:GetObject', 's3:PutObject'])));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.issue).toContain(ARTIFACT_BUCKET);
  });
});
