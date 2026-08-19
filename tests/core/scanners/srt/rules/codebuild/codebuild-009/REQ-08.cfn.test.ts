import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-08 (CODEBUILD-009): A project whose only S3 association is an S3 build-log
 * destination with Status DISABLED has no S3 bucket association, so the service
 * role does not need s3:GetBucketAcl / s3:GetBucketLocation.
 */

const factory = new Codebuild009CfnAdapterFactory();

// Policy that grants neither get-bucket-ACL nor get-bucket-location.
const rolePolicyDocument = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: ['s3:PutObject', 's3:GetObject'],
      Resource: 'arn:aws:s3:::build-logs-bucket/*',
    },
  ],
};

function buildTemplate(s3LogsStatus: string): Template {
  return {
    Resources: {
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
              PolicyName: 'build-policy',
              PolicyDocument: rolePolicyDocument,
            },
          ],
        },
      },
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // 'ProjectRole' is what !Ref ProjectRole resolves to after preprocessing.
          ServiceRole: 'ProjectRole',
          Artifacts: { Type: 'NO_ARTIFACTS' },
          Source: { Type: 'CODECOMMIT', Location: 'https://git-codecommit.us-east-1.amazonaws.com/v1/repos/app' },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          LogsConfig: {
            S3Logs: {
              Status: s3LogsStatus,
              Location: 'build-logs-bucket/logs',
            },
          },
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template): CfnContext {
  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, any>)['BuildProject'],
    logicalId: 'BuildProject',
  };
}

describe('CODEBUILD-009 REQ-08 (CloudFormation)', () => {
  it('passes when the S3 logs destination is DISABLED and the role grants neither bucket-inspection permission', () => {
    const context = contextFor(buildTemplate('DISABLED'));
    const adapter = factory.bind(context);

    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: primary behaviour owned by the base CODEBUILD-009 requirement.
  it('flags the same project when the S3 logs destination is ENABLED', () => {
    const context = contextFor(buildTemplate('ENABLED'));
    const adapter = factory.bind(context);

    const result = codebuild009Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.issue).toContain('build-logs-bucket');
  });
});
