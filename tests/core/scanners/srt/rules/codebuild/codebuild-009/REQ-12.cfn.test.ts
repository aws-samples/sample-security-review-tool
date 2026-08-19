import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-output-bucket';

/**
 * The template is written in its post-`parseCfnTemplate` form: the project's
 * `ServiceRole` was authored as `!GetAtt BuildRole.Arn`, which preprocessing
 * resolves to the logical id string `'BuildRole'`.
 */
function template(bucketActions: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
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
              PolicyName: 'artifact-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: bucketActions,
                    Resource: `arn:aws:s3:::${BUCKET}`,
                  },
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetObject', 's3:GetObjectVersion', 's3:PutObject'],
                    Resource: `arn:aws:s3:::${BUCKET}/*`,
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

function runProject(tpl: Template) {
  const resource = (tpl.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'build-stack',
    template: tpl,
    resource,
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation): S3 artifact bucket permissions on the service role', () => {
  // Primary behavior owned by CODEBUILD-009: GetBucketLocation plus object
  // read/write, but no GetBucketAcl, must be flagged.
  it('flags a project whose service role policy grants s3:GetBucketLocation but not s3:GetBucketAcl on the artifact bucket', () => {
    const result = runProject(template(['s3:GetBucketLocation']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.resourceType).toBe('AWS::CodeBuild::Project');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: identical template, only the missing action added back.
  it('does not flag the otherwise identical project when s3:GetBucketAcl is also allowed', () => {
    const result = runProject(template(['s3:GetBucketLocation', 's3:GetBucketAcl']));

    expect(result).toBeNull();
  });
});
