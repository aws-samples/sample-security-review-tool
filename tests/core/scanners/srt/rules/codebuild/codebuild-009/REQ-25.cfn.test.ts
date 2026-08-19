import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-25 (CODEBUILD-009): a project whose artifacts live in an S3 bucket passes when the
 * service role defined in the same template allows both s3:GetBucketAcl and
 * s3:GetBucketLocation on Resource "*", because a wildcard resource matches every bucket ARN.
 */

const ARTIFACT_BUCKET = 'my-artifact-bucket';

function buildTemplate(roleActions: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // !GetAtt BuildRole.Arn resolves to the logical id after preprocessing
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: ARTIFACT_BUCKET,
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
              PolicyName: 'BuildAccess',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: roleActions,
                    Resource: '*',
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

function runControl(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-25 (CloudFormation)', () => {
  it('passes when the service role allows both bucket-inspection actions on Resource "*"', () => {
    const template = buildTemplate(['s3:GetBucketAcl', 's3:GetBucketLocation']);

    expect(runControl(template)).toBeNull();
  });

  // Opposite outcome: the wildcard resource is unchanged, but one required action is absent,
  // so the requirement is no longer satisfied for the artifact bucket.
  it('flags the project when the wildcard statement omits s3:GetBucketAcl', () => {
    const template = buildTemplate(['s3:GetBucketLocation']);

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(ARTIFACT_BUCKET);
  });
});
