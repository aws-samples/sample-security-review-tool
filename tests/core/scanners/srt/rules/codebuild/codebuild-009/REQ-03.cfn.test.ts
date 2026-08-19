import { describe, it, expect } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const CACHE_BUCKET = 'my-cache-bucket';

/**
 * REQ-03 (CODEBUILD-009): a project whose only S3 association is its S3 build
 * cache, running under an in-template role that allows both
 * s3:GetBucketAcl and s3:GetBucketLocation on that bucket, passes.
 */
function buildTemplate(cacheActions: string[]): Template {
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
              PolicyName: 'cache-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: cacheActions,
                    Resource: [
                      `arn:aws:s3:::${CACHE_BUCKET}`,
                      `arn:aws:s3:::${CACHE_BUCKET}/*`,
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
          // ServiceRole written as !GetAtt BuildRole.Arn resolves to the logical id
          ServiceRole: 'BuildRole',
          Artifacts: { Type: 'NO_ARTIFACTS' },
          Source: { Type: 'GITHUB', Location: 'https://github.com/example/repo.git' },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          Cache: { Type: 'S3', Location: `${CACHE_BUCKET}/cache-prefix` },
        },
      },
    },
  } as unknown as Template;
}

function runOnProject(template: Template) {
  const resources = (template as { Resources?: Record<string, any> }).Resources ?? {};
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-03 (CloudFormation)', () => {
  it('passes when the in-template service role allows both bucket-inspection actions on the S3 cache bucket', () => {
    const result = runOnProject(buildTemplate(['s3:GetBucketAcl', 's3:GetBucketLocation']));
    expect(result).toBeNull();
  });

  // Opposite outcome: the pair of permissions is what the requirement turns on.
  it('flags the project when the role allows only s3:GetBucketAcl on the same cache bucket', () => {
    const result = runOnProject(buildTemplate(['s3:GetBucketAcl']));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(CACHE_BUCKET);
  });
});
