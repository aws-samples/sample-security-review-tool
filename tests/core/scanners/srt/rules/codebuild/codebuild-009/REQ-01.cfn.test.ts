import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifacts-bucket';
const BUCKET_ARN = `arn:aws:s3:::${BUCKET}`;

/**
 * Builds a template where the project's only S3 association is its artifacts
 * bucket, and its in-template service role has an inline policy allowing the
 * given actions on that bucket. Nothing denies anything.
 */
function buildTemplate(allowedActions: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          // ServiceRole written as !GetAtt BuildRole.Arn resolves to the logical id
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
            Name: 'output.zip',
          },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          Source: {
            Type: 'GITHUB',
            Location: 'https://github.com/example/repo.git',
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
              PolicyName: 'artifacts-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: allowedActions,
                    Resource: BUCKET_ARN,
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

function runOnProject(template: Template) {
  const factory = new Codebuild009CfnAdapterFactory();
  const resource = (template.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'BuildProject',
  };
  const adapter = factory.bind(context);
  return codebuild009Control.run(adapter as any, context);
}

describe('CODEBUILD-009 (CloudFormation) - role must allow s3:GetBucketAcl and s3:GetBucketLocation on associated bucket', () => {
  // Primary behaviour owned by this requirement: both required permissions allowed => pass
  it('passes when the in-template role policy allows both get-bucket-ACL and get-bucket-location on the artifacts bucket', () => {
    const template = buildTemplate(['s3:GetBucketAcl', 's3:GetBucketLocation']);
    expect(runOnProject(template)).toBeNull();
  });

  // Opposite outcome: same fixture, but only one of the two required permissions is allowed
  it('flags the project when the role policy allows get-bucket-ACL but not get-bucket-location on that bucket', () => {
    const template = buildTemplate(['s3:GetBucketAcl']);
    const result = runOnProject(template);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
  });
});
