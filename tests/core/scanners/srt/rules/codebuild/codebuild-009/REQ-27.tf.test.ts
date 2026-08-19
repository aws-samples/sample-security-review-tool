import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.tf.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifacts-bucket';
const factory = new Codebuild009TfAdapterFactory();

const unresolved = (expression: string): string => `__unresolved__:${expression}`;

function scan(resources: TerraformResource[], address: string): ScanResult | null {
  const resource = resources.find(candidate => candidate.address === address)!;
  const context: TfContext = {
    projectName: 'test-project',
    resource,
    allResources: resources,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

/** Project writes artifacts to an S3 bucket; only the role reference varies. */
function project(serviceRole: string): TerraformResource {
  return {
    type: 'aws_codebuild_project',
    name: 'build',
    address: 'aws_codebuild_project.build',
    values: {
      name: 'build',
      service_role: serviceRole,
      artifacts: [{ type: 'S3', location: BUCKET }],
      source: [{ type: 'NO_SOURCE' }],
    },
  } as TerraformResource;
}

describe('CODEBUILD-009 (Terraform) - unresolvable service role identity', () => {
  // Primary behavior owned by this requirement: unresolved role identity => no finding.
  it('does not flag a project whose service_role comes from a variable with no reachable default', () => {
    const resources = [project(unresolved('var.codebuild_service_role_arn'))];

    expect(scan(resources, 'aws_codebuild_project.build')).toBeNull();
  });

  // Opposite outcome: identical project, but service_role references a real role
  // whose policy omits s3:GetBucketLocation.
  it('flags a project whose resolvable service role lacks one of the required bucket-inspection permissions', () => {
    const role: TerraformResource = {
      type: 'aws_iam_role',
      name: 'build',
      address: 'aws_iam_role.build',
      values: { name: 'codebuild-build-role' },
    } as TerraformResource;

    const rolePolicy: TerraformResource = {
      type: 'aws_iam_role_policy',
      name: 'artifacts',
      address: 'aws_iam_role_policy.artifacts',
      values: {
        role: 'aws_iam_role.build',
        policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: ['s3:GetBucketAcl', 's3:PutObject'],
              Resource: [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`],
            },
          ],
        }),
      },
    } as TerraformResource;

    const resources = [project('aws_iam_role.build'), role, rolePolicy];

    const result = scan(resources, 'aws_codebuild_project.build');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('aws_codebuild_project.build');
    expect(result?.issue).toContain(BUCKET);
  });
});
