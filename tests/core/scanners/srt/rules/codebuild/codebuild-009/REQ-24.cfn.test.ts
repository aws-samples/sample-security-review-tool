import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Codebuild009CfnAdapterFactory();

/**
 * REQ-24 (CODEBUILD-009): the project's service role must effectively allow
 * both s3:GetBucketAcl and s3:GetBucketLocation on every S3 bucket the project
 * uses. Here the grants are scoped exclusively to an unrelated bucket ARN.
 */
function buildTemplate(grantedBucketArn: string): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          // ServiceRole: !Ref BuildRole resolves to the logical ID string
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: 'artifact-bucket',
            Name: 'output.zip',
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
              PolicyName: 'bucket-inspection',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                    Resource: grantedBucketArn,
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

function runOn(template: Template) {
  const resource = (template.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'BuildProject',
  };
  return codebuild009Control.run(factory.bind(context) as any, context);
}

describe('CODEBUILD-009 REQ-24 (CloudFormation)', () => {
  it('flags a project whose role grants the bucket-inspection actions only on an unrelated bucket', () => {
    const result = runOn(buildTemplate('arn:aws:s3:::unrelated-bucket'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain('artifact-bucket');
  });

  // Opposite outcome: the nearest input that flips the verdict is the same
  // grant scoped to the project's actual artifact bucket instead.
  it('does not flag when the same grants are scoped to the project artifact bucket', () => {
    const result = runOn(buildTemplate('arn:aws:s3:::artifact-bucket'));

    expect(result).toBeNull();
  });
});
