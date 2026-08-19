import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const PROJECT_NAME = 'codebuild-009-project';
const BUCKET = 'my-artifact-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET}`;
const ROLE_ADDRESS = 'aws_iam_role.codebuild';

function policyJson(action: string): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: [action], Resource: [BUCKET_ARN] }],
  });
}

/**
 * Project storing build artifacts in an S3 bucket, running under a role that
 * gets `s3:GetBucketAcl` from a policy embedded in the role
 * (aws_iam_role_policy) and `separatePolicyAction` from a separately declared
 * policy document (aws_iam_policy) associated with the same role.
 */
function buildResources(separatePolicyAction: string): TerraformResource[] {
  const project: TerraformResource = {
    type: 'aws_codebuild_project',
    name: 'demo',
    address: 'aws_codebuild_project.demo',
    values: {
      name: 'demo-project',
      service_role: ROLE_ADDRESS,
      artifacts: [{ type: 'S3', location: BUCKET }],
      source: [{ type: 'GITHUB', location: 'https://github.com/example/repo.git' }],
    },
  };

  const role: TerraformResource = {
    type: 'aws_iam_role',
    name: 'codebuild',
    address: ROLE_ADDRESS,
    values: { name: 'codebuild-service-role' },
  };

  const embeddedPolicy: TerraformResource = {
    type: 'aws_iam_role_policy',
    name: 'embedded',
    address: 'aws_iam_role_policy.embedded',
    values: { role: ROLE_ADDRESS, name: 'embedded-in-role', policy: policyJson('s3:GetBucketAcl') },
  };

  const separatePolicy: TerraformResource = {
    type: 'aws_iam_policy',
    name: 'separate',
    address: 'aws_iam_policy.separate',
    values: { name: 'separately-declared', policy: policyJson(separatePolicyAction) },
  };

  const attachment: TerraformResource = {
    type: 'aws_iam_role_policy_attachment',
    name: 'separate',
    address: 'aws_iam_role_policy_attachment.separate',
    values: { role: ROLE_ADDRESS, policy_arn: 'aws_iam_policy.separate' },
  };

  return [project, role, embeddedPolicy, separatePolicy, attachment];
}

function runOnProject(resources: TerraformResource[]): ScanResult | null {
  const project = resources[0];
  const context: TfContext = {
    projectName: PROJECT_NAME,
    resource: project,
    allResources: resources,
  };
  const adapter = new Codebuild009TfAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (Terraform): permissions split across an embedded role policy and a separately declared policy', () => {
  // Primary behaviour owned by CODEBUILD-009: IAM evaluates all identity-based
  // policies on the role together, so the split source of the two permissions
  // does not matter.
  it('passes when get-bucket-ACL comes from the role-embedded policy and get-bucket-location from a separately declared policy', () => {
    const result = runOnProject(buildResources('s3:GetBucketLocation'));

    expect(result).toBeNull();
  });

  it('flags the project when the separately declared policy grants an unrelated action instead of get-bucket-location', () => {
    const result = runOnProject(buildResources('s3:GetObject'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.demo');
    expect(result?.issue).toContain(BUCKET);
  });
});
