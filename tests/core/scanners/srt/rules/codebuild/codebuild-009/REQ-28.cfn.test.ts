import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-28 (CODEBUILD-009): CodeBuild project service roles must include both
 * s3:GetBucketAcl and s3:GetBucketLocation for any S3 bucket associated with
 * the project.
 *
 * Scenario under test: the project writes artifacts to an S3 bucket and its
 * service role is defined in the same template, but the policy's list of
 * allowed actions comes from a deployment-time input (an unresolved intrinsic).
 * The scanner cannot know whether the required actions are present, so it must
 * not assert a breach.
 */

const ARTIFACT_BUCKET = 'build-artifacts-bucket';

function buildTemplate(actions: unknown): Template {
  return {
    Parameters: {
      AllowedActions: { Type: 'String' },
    },
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          ServiceRole: 'BuildRole', // !GetAtt BuildRole.Arn resolves to the logical id
          Artifacts: {
            Type: 'S3',
            Location: ARTIFACT_BUCKET,
          },
          Source: {
            Type: 'NO_SOURCE',
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
              PolicyName: 'ArtifactAccess',
              PolicyDocument: {
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
              },
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const factory = new Codebuild009CfnAdapterFactory();
  const resource = (template.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'BuildProject',
  };
  return codebuild009Control.run(factory.bind(context), context);
}

describe('CODEBUILD-009 (CloudFormation) - REQ-28', () => {
  it('passes when the policy actions come from an unresolvable deployment-time input', () => {
    // Fn::Split over a template parameter is left intact by preprocessing,
    // so the action list is unknown to the scanner.
    const template = buildTemplate({
      'Fn::Split': [',', { Ref: 'AllowedActions' }],
    });

    expect(runControl(template)).toBeNull();
  });

  // Opposite outcome: identical fixture, but the action list is a known literal
  // that omits the required bucket-inspection actions. This behaviour is owned
  // by CODEBUILD-009's primary requirement; it is included here so the file
  // discriminates a real evaluation from a control that never flags.
  it('flags when the same policy lists known actions that omit the required permissions', () => {
    const template = buildTemplate(['s3:GetObject', 's3:PutObject']);

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.issue).toContain(ARTIFACT_BUCKET);
  });
});
