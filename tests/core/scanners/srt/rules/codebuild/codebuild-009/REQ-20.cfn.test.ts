import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009CfnAdapterFactory();

/**
 * The project stores its build output artifacts in an S3 bucket and runs under a
 * role declared in the same template. `ServiceRole: 'BuildRole'` is what
 * `!GetAtt BuildRole.Arn` resolves to after template preprocessing.
 */
function buildTemplate(rolePolicyStatement: Record<string, unknown>): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: 'my-artifact-bucket',
            Name: 'output',
          },
          Source: {
            Type: 'GITHUB',
            Location: 'https://github.com/example/repo.git',
          },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
        },
      },
      BuildRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { Service: 'codebuild.amazonaws.com' },
                Action: 'sts:AssumeRole',
              },
            ],
          },
          Policies: [
            {
              PolicyName: 'BuildPolicy',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [rolePolicyStatement],
              },
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function bind(template: Template, logicalId: string): { adapter: Codebuild009Adapter; context: CfnContext } {
  const resource = (template.Resources as Record<string, Resource>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  return { adapter: factory.bind(context) as Codebuild009Adapter, context };
}

describe('CODEBUILD-009 (CloudFormation) - wildcard admin policy satisfies bucket inspection permissions', () => {
  it('does not flag a project whose in-template service role allows every action on every resource', () => {
    const template = buildTemplate({
      Effect: 'Allow',
      Action: '*',
      Resource: '*',
    });
    const { adapter, context } = bind(template, 'BuildProject');

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the statement is
  // still present and still allows an S3 bucket-inspection action, but it omits
  // s3:GetBucketLocation, so the required permission set is incomplete.
  it('flags the same project when the policy allows only one of the two required actions', () => {
    const template = buildTemplate({
      Effect: 'Allow',
      Action: ['s3:GetBucketAcl'],
      Resource: '*',
    });
    const { adapter, context } = bind(template, 'BuildProject');

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual(['my-artifact-bucket']);
    const result = codebuild009Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
  });
});
