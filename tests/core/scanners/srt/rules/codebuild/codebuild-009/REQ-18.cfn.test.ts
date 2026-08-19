import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';

/**
 * Builds a template where the project writes its artifacts to an S3 bucket and
 * runs under a role declared in the same template whose only inline policy
 * statement allows `action` on that bucket.
 */
function buildTemplate(action: string): Template {
  return {
    Resources: {
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
              PolicyName: 'artifact-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: action,
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
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // Resolved value of !GetAtt BuildRole.Arn after preprocessing.
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
    },
  } as unknown as Template;
}

function contextFor(template: Template): CfnContext {
  const resources = template.Resources as Record<string, any>;
  return {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
}

function runControl(template: Template) {
  const context = contextFor(template);
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation) - full-service S3 wildcard on the artifact bucket', () => {
  // Primary behavior owned by CODEBUILD-009: s3:* covers s3:GetBucketAcl and
  // s3:GetBucketLocation, so the required permissions are present.
  it('passes when the service role policy allows s3:* on the project artifact bucket', () => {
    expect(runControl(buildTemplate('s3:*'))).toBeNull();
  });

  // Opposite outcome: the same statement, but the allowed action is a real S3
  // action that is neither of the two required bucket-inspection permissions.
  it('flags when the service role policy allows only a non-qualifying S3 action on the artifact bucket', () => {
    const result = runControl(buildTemplate('s3:GetObject'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
