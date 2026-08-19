import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifacts-bucket';
const PROJECT_ID = 'BuildProject';
const ROLE_ID = 'BuildRole';

/**
 * REQ-11 (CODEBUILD-009): a project that stores artifacts in an S3 bucket must run
 * under a service role that allows BOTH s3:GetBucketAcl and s3:GetBucketLocation.
 */
function buildTemplate(bucketActions: string[]): Template {
  return {
    Resources: {
      [PROJECT_ID]: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'build-project',
          // ServiceRole was written as !Ref BuildRole; preprocessing resolves it to the logical id.
          ServiceRole: ROLE_ID,
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
      } as unknown as Resource,
      [ROLE_ID]: {
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
                    Action: bucketActions,
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
      } as unknown as Resource,
    },
  } as Template;
}

function evaluateProject(template: Template) {
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: template.Resources![PROJECT_ID],
    logicalId: PROJECT_ID,
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-11 (CloudFormation)', () => {
  it('flags a project whose role policy allows get-bucket-ACL and object read/write but omits get-bucket-location', () => {
    const result = evaluateProject(
      buildTemplate(['s3:GetBucketAcl', 's3:GetObject', 's3:GetObjectVersion', 's3:PutObject']),
    );

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('CODEBUILD-009');
    expect(result!.resourceName).toBe(PROJECT_ID);
    expect(result!.issue).toContain(BUCKET);
  });

  // Opposite outcome: the only change is that the missing permission is present.
  it('does not flag the same project when the role policy also allows get-bucket-location', () => {
    const result = evaluateProject(
      buildTemplate([
        's3:GetBucketAcl',
        's3:GetBucketLocation',
        's3:GetObject',
        's3:GetObjectVersion',
        's3:PutObject',
      ]),
    );

    expect(result).toBeNull();
  });
});
