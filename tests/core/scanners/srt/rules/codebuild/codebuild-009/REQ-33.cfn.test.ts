import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';
const BUCKET_ARNS = [`arn:aws:s3:::${BUCKET}`, `arn:aws:s3:::${BUCKET}/*`];

function template(actions: string[]): Template {
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
              PolicyName: 'artifact-bucket-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: actions,
                    Resource: BUCKET_ARNS,
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
          // Service role reference resolves to the logical id 'BuildRole'
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
            Name: 'build-output',
          },
          Source: {
            Type: 'GITHUB',
            Location: 'https://github.com/example/repo.git',
          },
          Environment: {
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
            Type: 'LINUX_CONTAINER',
          },
        },
      },
    },
  } as unknown as Template;
}

function run(actions: string[]) {
  const tpl = template(actions);
  const resource = (tpl.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template: tpl,
    resource,
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation) - wildcard action patterns grant the required bucket-inspection permissions', () => {
  // Primary behaviour owned by CODEBUILD-009: exact GetBucketAcl plus a
  // wildcard covering GetBucketLocation, both scoped to the artifact bucket.
  it('passes when get-bucket-ACL is named exactly and get-bucket-location is covered by a wildcard action', () => {
    const result = run(['s3:GetBucketAcl', 's3:GetBucket*']);
    expect(result).toBeNull();
  });

  // Opposite outcome: the wildcard is still present but does not match
  // s3:GetBucketLocation, so the permission is not effectively granted.
  it('flags when the wildcard action pattern does not match get-bucket-location', () => {
    const result = run(['s3:GetBucketAcl', 's3:GetObject*']);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
