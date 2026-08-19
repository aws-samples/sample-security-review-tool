import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifact-bucket';

/**
 * REQ-19 (CODEBUILD-009): a project whose artifacts live in an S3 bucket passes when its
 * in-template service role is allowed an action wildcard that covers both
 * s3:GetBucketAcl and s3:GetBucketLocation on that bucket.
 */
function buildTemplate(action: string): Template {
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
              PolicyName: 'BucketInspection',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: action,
                    Resource: [
                      `arn:aws:s3:::${BUCKET}`,
                      `arn:aws:s3:::${BUCKET}/*`,
                    ],
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
          // !GetAtt BuildRole.Arn resolves to the logical id after preprocessing
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
            Name: 'output',
          },
          Environment: {
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
            Type: 'LINUX_CONTAINER',
          },
          Source: {
            Type: 'NO_SOURCE',
            BuildSpec: 'version: 0.2',
          },
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template) {
  const resources = (template as { Resources: Record<string, any> }).Resources;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-19 (CloudFormation)', () => {
  it('passes when the service role allows the s3:Get* wildcard on the project artifact bucket', () => {
    expect(runControl(buildTemplate('s3:Get*'))).toBeNull();
  });

  // Opposite outcome: a get-verb wildcard that is narrowed to object actions covers
  // neither s3:GetBucketAcl nor s3:GetBucketLocation, so the project must be flagged.
  it('flags the project when the wildcard is narrowed to s3:GetObject* and covers neither required action', () => {
    const result = runControl(buildTemplate('s3:GetObject*'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
