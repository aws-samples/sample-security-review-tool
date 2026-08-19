import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';
const REQUIRED_ACTIONS = ['s3:GetBucketAcl', 's3:GetBucketLocation'];

/**
 * ServiceRole is written in real templates as !GetAtt BuildRole.Arn, which
 * preprocessing collapses to the logical id string 'BuildRole'.
 */
function template(effect: 'Allow' | 'Deny'): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
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
              PolicyName: 'ArtifactBucketAccess',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: effect,
                    Action: REQUIRED_ACTIONS,
                    Resource: [
                      `arn:aws:s3:::${BUCKET}`,
                      `arn:aws:s3:::${BUCKET}/*`,
                    ],
                  },
                ],
              },
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function bindProject(tpl: Template): { adapter: Codebuild009Adapter; context: CfnContext } {
  const context: CfnContext = {
    stackName: 'test-stack',
    template: tpl,
    resource: (tpl.Resources as Record<string, any>)['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return { adapter, context };
}

describe('CODEBUILD-009 (CloudFormation) - artifact bucket permissions granted with a denying effect', () => {
  // Primary behaviour owned by CODEBUILD-009: a Deny statement grants nothing.
  it('flags a project whose in-template service role denies both required bucket actions on the artifact bucket', () => {
    const { adapter, context } = bindProject(template('Deny'));

    const result = codebuild009Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(adapter.bucketsMissingRequiredPermissions()).toContain(BUCKET);
  });

  // Opposite outcome: identical fixture, only the statement effect flips to Allow.
  it('does not flag the same project when the statement effect allows both required bucket actions', () => {
    const { adapter, context } = bindProject(template('Allow'));

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });
});
