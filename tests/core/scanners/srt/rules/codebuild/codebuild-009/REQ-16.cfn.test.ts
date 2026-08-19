import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'codebuild-009-stack';
const BUCKET = 'my-artifact-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET}`;
const ROLE_LOGICAL_ID = 'CodeBuildServiceRole';

/**
 * Statement granting a single S3 action on the project's artifact bucket.
 */
function statement(action: string): Record<string, unknown> {
  return { Effect: 'Allow', Action: [action], Resource: [BUCKET_ARN] };
}

/**
 * A project that writes its build artifacts to an S3 bucket. Its service role
 * carries an embedded (inline) policy granting `s3:GetBucketAcl`, plus a
 * separately declared policy document (AWS::IAM::Policy) attached to the same
 * role granting `separatePolicyAction`.
 */
function buildTemplate(separatePolicyAction: string): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          // !Ref CodeBuildServiceRole resolves to the logical id string
          ServiceRole: ROLE_LOGICAL_ID,
          Artifacts: { Type: 'S3', Location: BUCKET },
          Source: { Type: 'GITHUB', Location: 'https://github.com/example/repo.git' },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
        },
      },
      [ROLE_LOGICAL_ID]: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              { Effect: 'Allow', Principal: { Service: 'codebuild.amazonaws.com' }, Action: 'sts:AssumeRole' },
            ],
          },
          Policies: [
            {
              PolicyName: 'embedded-in-role',
              PolicyDocument: { Version: '2012-10-17', Statement: [statement('s3:GetBucketAcl')] },
            },
          ],
        },
      },
      SeparatelyDeclaredPolicy: {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'separately-declared',
          Roles: [ROLE_LOGICAL_ID],
          PolicyDocument: { Version: '2012-10-17', Statement: [statement(separatePolicyAction)] },
        },
      },
    },
  } as unknown as Template;
}

function runOnProject(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation): permissions split across an embedded role policy and a separately declared policy', () => {
  // Primary behaviour owned by CODEBUILD-009: the role's effective permissions
  // are the union of every identity-based policy associated with it.
  it('passes when get-bucket-ACL comes from the role\'s embedded policy and get-bucket-location from a separately declared policy', () => {
    const result = runOnProject(buildTemplate('s3:GetBucketLocation'));

    expect(result).toBeNull();
  });

  it('flags the project when the separately declared policy grants an unrelated action instead of get-bucket-location', () => {
    const result = runOnProject(buildTemplate('s3:GetObject'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
