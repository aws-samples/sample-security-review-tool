import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (CODEBUILD-009): the rule only requires s3:GetBucketAcl and
 * s3:GetBucketLocation for S3 buckets that the project actually associates.
 * A project with a git-provider source, NO_ARTIFACTS output, no cache and
 * CloudWatch-only logs associates no bucket, so a role policy granting neither
 * action is compliant.
 */

const factory = new Codebuild009CfnAdapterFactory();

// Role policy that deliberately grants neither of the two required actions.
const roleWithoutBucketInspectionPermissions = {
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
        PolicyName: 'build-permissions',
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: ['logs:CreateLogStream', 'logs:PutLogEvents', 's3:GetObject'],
              Resource: '*',
            },
          ],
        },
      },
    ],
  },
};

function buildTemplate(projectProperties: Record<string, unknown>): Template {
  return {
    Resources: {
      BuildRole: roleWithoutBucketInspectionPermissions,
      Project: {
        Type: 'AWS::CodeBuild::Project',
        Properties: projectProperties,
      },
    },
  } as unknown as Template;
}

const baseProjectProperties = {
  Name: 'git-sourced-project',
  // !Ref BuildRole resolves to the logical id string after preprocessing.
  ServiceRole: 'BuildRole',
  Environment: {
    ComputeType: 'BUILD_GENERAL1_SMALL',
    Image: 'aws/codebuild/standard:7.0',
    Type: 'LINUX_CONTAINER',
  },
  Source: {
    Type: 'GITHUB',
    Location: 'https://github.com/example-org/example-repo.git',
  },
  Artifacts: { Type: 'NO_ARTIFACTS' },
  LogsConfig: {
    CloudWatchLogs: { Status: 'ENABLED', GroupName: '/aws/codebuild/git-sourced-project' },
  },
};

function contextFor(template: Template): CfnContext {
  return {
    stackName: 'test-stack',
    template,
    resource: (template.Resources as Record<string, any>)['Project'],
    logicalId: 'Project',
  };
}

describe('CODEBUILD-009 REQ-07 (CloudFormation)', () => {
  it('passes when the project associates no S3 bucket and the role grants neither required action', () => {
    const template = buildTemplate(baseProjectProperties);
    const context = contextFor(template);
    const adapter = factory.bind(context) as any;

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: same project and same permission-less role, but the build
  // output is now an S3 bucket, so a bucket IS associated. Primary behavior for
  // the flagged case belongs to the missing-permissions requirement.
  it('flags the otherwise identical project once an S3 artifact bucket is associated', () => {
    const template = buildTemplate({
      ...baseProjectProperties,
      Artifacts: { Type: 'S3', Location: 'build-output-bucket' },
    });
    const context = contextFor(template);
    const adapter = factory.bind(context) as any;

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual(['build-output-bucket']);

    const result = codebuild009Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('Project');
  });
});
