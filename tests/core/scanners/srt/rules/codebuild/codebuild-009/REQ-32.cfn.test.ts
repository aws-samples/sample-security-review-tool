import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ARTIFACTS_BUCKET = 'artifacts-bucket';
const CACHE_BUCKET = 'cache-bucket';

const REQUIRED_ACTIONS = ['s3:GetBucketAcl', 's3:GetBucketLocation'];

/**
 * Template as the rule sees it AFTER parseCfnTemplate: the project's
 * ServiceRole (authored as !GetAtt BuildRole.Arn) has already collapsed to the
 * logical id string 'BuildRole'.
 */
function template(policyBucketArns: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: ARTIFACTS_BUCKET,
          },
          Cache: {
            Type: 'S3',
            Location: CACHE_BUCKET,
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
                    Action: REQUIRED_ACTIONS,
                    Resource: policyBucketArns,
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

function evaluateProject(tpl: Template): ScanResult | null {
  const resources = tpl.Resources as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template: tpl,
    resource: resources['BuildProject'],
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 (CloudFormation): required bucket-inspection permissions must cover every associated bucket', () => {
  it('flags the project when the permissions are scoped only to the artifacts bucket, leaving the S3 cache bucket uncovered', () => {
    const result = evaluateProject(template([`arn:aws:s3:::${ARTIFACTS_BUCKET}`]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(CACHE_BUCKET);
  });

  // Opposite outcome: same template, the only change is that the identical
  // allow statement also covers the cache bucket, so nothing is uncovered.
  it('does not flag the project when the same permissions cover both the artifacts bucket and the cache bucket', () => {
    const result = evaluateProject(
      template([`arn:aws:s3:::${ARTIFACTS_BUCKET}`, `arn:aws:s3:::${CACHE_BUCKET}`]),
    );

    expect(result).toBeNull();
  });
});
