import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifacts-bucket';
const factory = new Codebuild009CfnAdapterFactory();

/**
 * Templates below are written as they appear AFTER parseCfnTemplate: the
 * project's ServiceRole is the logical ID string that `!GetAtt Role.Arn`
 * resolves to.
 */
function buildTemplate(policyResources: string[]): Template {
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
              PolicyName: 'artifact-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetBucketAcl', 's3:GetBucketLocation'],
                    Resource: policyResources,
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
          ServiceRole: 'ProjectRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
          },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          Source: {
            Type: 'NO_SOURCE',
          },
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resources = template.Resources as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  return codebuild009Control.run(factory.bind(context), context);
}

describe('CODEBUILD-009 (CloudFormation) — bucket-level permissions scoped only to objects', () => {
  // Primary behaviour owned by CODEBUILD-009: bucket-level actions granted only
  // on the object ARN do not cover the bucket itself.
  it('flags a project whose role allows both actions only on objects inside the artifact bucket', () => {
    const result = run(buildTemplate([`arn:aws:s3:::${BUCKET}/*`]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });

  // Opposite outcome: same grant, but the resource is the bucket ARN itself.
  it('does not flag when the same two actions are scoped to the bucket ARN itself', () => {
    const result = run(buildTemplate([`arn:aws:s3:::${BUCKET}`]));

    expect(result).toBeNull();
  });
});
