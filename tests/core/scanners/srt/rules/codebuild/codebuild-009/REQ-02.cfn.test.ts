import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET_ARN = 'arn:aws:s3:::my-source-bucket';

function buildTemplate(actions: string[]): Template {
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
              PolicyName: 'source-bucket-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: actions,
                    Resource: BUCKET_ARN,
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
          Name: 'demo-project',
          // ServiceRole authored as !GetAtt BuildRole.Arn resolves to the logical id.
          ServiceRole: 'BuildRole',
          Source: {
            Type: 'S3',
            Location: 'my-source-bucket/source.zip',
          },
          Artifacts: {
            Type: 'NO_ARTIFACTS',
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

function runOnProject(template: Template) {
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

describe('CODEBUILD-009 CloudFormation - S3 source bucket with NO_ARTIFACTS output', () => {
  // Primary behavior owned by CODEBUILD-009: role grants both required bucket-inspection permissions.
  it('passes when the in-template service role allows both s3:GetBucketAcl and s3:GetBucketLocation on the S3 source bucket', () => {
    const result = runOnProject(buildTemplate(['s3:GetBucketAcl', 's3:GetBucketLocation', 's3:GetObject']));
    expect(result).toBeNull();
  });

  // Opposite outcome: identical template except one of the two required actions is absent from the allow statement.
  it('flags the project when the service role policy allows only s3:GetBucketLocation on the S3 source bucket', () => {
    const result = runOnProject(buildTemplate(['s3:GetBucketLocation', 's3:GetObject']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain('my-source-bucket');
  });
});
