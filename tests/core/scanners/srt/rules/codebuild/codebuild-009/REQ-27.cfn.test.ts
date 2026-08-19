import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'build-artifacts-bucket';
const factory = new Codebuild009CfnAdapterFactory();

function scan(template: Record<string, unknown>, logicalId: string): ScanResult | null {
  const tpl = template as unknown as Template;
  const resource = (tpl.Resources as Record<string, Resource>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template: tpl,
    resource,
    logicalId,
  };
  return codebuild009Control.run(factory.bind(context), context);
}

/**
 * Project artifacts land in an S3 bucket, but the service role identity is a
 * cross-stack (deployment-time) input that preprocessing leaves as an opaque
 * object, so the scanner cannot resolve the role or read its policies.
 */
function templateWithServiceRole(serviceRole: unknown, extraResources: Record<string, unknown> = {}) {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          ServiceRole: serviceRole,
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
          },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          Source: { Type: 'NO_SOURCE' },
        },
      },
      ...extraResources,
    },
  };
}

describe('CODEBUILD-009 (CloudFormation) - unresolvable service role identity', () => {
  // Primary behavior owned by this requirement: unresolved role identity => no finding.
  it('does not flag a project whose service role comes from an unresolved deployment-time input', () => {
    const template = templateWithServiceRole({ 'Fn::ImportValue': 'SharedCodeBuildRoleArn' });

    expect(scan(template, 'BuildProject')).toBeNull();
  });

  // Opposite outcome: identical project, but the role identity IS resolvable and
  // the resolved role's policy omits s3:GetBucketLocation.
  it('flags a project whose resolvable service role lacks one of the required bucket-inspection permissions', () => {
    const template = templateWithServiceRole('BuildRole', {
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
              PolicyName: 'artifacts',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetBucketAcl', 's3:PutObject'],
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
    });

    const result = scan(template, 'BuildProject');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
    expect(result?.issue).toContain(BUCKET);
  });
});
