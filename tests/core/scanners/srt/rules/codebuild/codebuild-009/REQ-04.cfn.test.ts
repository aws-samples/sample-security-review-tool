import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009CfnAdapterFactory();

function policyDocument(actions: string[]): Record<string, unknown> {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: actions,
        Resource: ['arn:aws:s3:::log-bucket', 'arn:aws:s3:::log-bucket/*'],
      },
    ],
  };
}

// Project's only S3 association is its build-log bucket; role is in-template.
function buildTemplate(roleActions: string[]): Template {
  return {
    Resources: {
      // Values shown are post-`parseCfnTemplate`: `!Ref ProjectRole` resolves to 'ProjectRole'.
      Project: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          ServiceRole: 'ProjectRole',
          Artifacts: { Type: 'NO_ARTIFACTS' },
          Source: { Type: 'GITHUB', Location: 'https://github.com/example/repo.git' },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          LogsConfig: {
            S3Logs: {
              Status: 'ENABLED',
              Location: 'log-bucket/build-logs',
            },
          },
        },
      },
      ProjectRole: {
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
              PolicyName: 'log-bucket-access',
              PolicyDocument: policyDocument(roleActions),
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template) {
  const resource = (template.Resources as Record<string, any>)['Project'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'Project',
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 CloudFormation - REQ-04', () => {
  // Primary behavior owned by this requirement: both permissions granted on the
  // only associated bucket (the build-log bucket) => compliant.
  it('passes when the in-template service role allows both get-bucket-ACL and get-bucket-location on the log bucket', () => {
    const result = run(buildTemplate(['s3:PutObject', 's3:GetBucketAcl', 's3:GetBucketLocation']));
    expect(result).toBeNull();
  });

  // Opposite outcome: same template, one of the required permissions is absent
  // from the otherwise-present statement.
  it('flags the project when the role policy allows get-bucket-ACL but not get-bucket-location', () => {
    const result = run(buildTemplate(['s3:PutObject', 's3:GetBucketAcl']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('Project');
    expect(result?.issue).toContain('log-bucket');
  });
});
