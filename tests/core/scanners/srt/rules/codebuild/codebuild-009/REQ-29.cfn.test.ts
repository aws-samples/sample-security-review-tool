import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-29 (CODEBUILD-009): a CodeBuild project whose artifact bucket name comes from a
 * deployment-time input that analysis cannot resolve must NOT be flagged, even though the
 * service role only allows s3:GetBucketAcl / s3:GetBucketLocation on a fixed, explicitly
 * named bucket -- the unresolved input may resolve to that very bucket.
 */

const FIXED_BUCKET = 'fixed-artifacts-bucket';

function roleWithBothPermissions() {
  return {
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
                Resource: `arn:aws:s3:::${FIXED_BUCKET}`,
              },
            ],
          },
        },
      ],
    },
  };
}

function templateWithArtifactLocation(location: unknown): Template {
  return {
    Resources: {
      BuildRole: roleWithBothPermissions(),
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'demo-project',
          // { Ref: 'BuildRole' } resolves to the logical id string during preprocessing.
          ServiceRole: 'BuildRole',
          Source: { Type: 'NO_SOURCE' },
          Artifacts: { Type: 'S3', Location: location },
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
        },
      },
    },
  } as unknown as Template;
}

function evaluateProject(template: Template) {
  const resource = (template.Resources as Record<string, any>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context);
  return codebuild009Control.run(adapter, context);
}

describe('CODEBUILD-009 REQ-29 (CloudFormation)', () => {
  it('passes when the artifact bucket name is an unresolved deployment-time input', () => {
    // Fn::ImportValue is left intact by preprocessing: the bucket name is unknowable.
    const template = templateWithArtifactLocation({ 'Fn::ImportValue': 'ArtifactBucketName' });

    expect(evaluateProject(template)).toBeNull();
  });

  /**
   * Opposite outcome: the requirement is owned by CODEBUILD-009's core check. With a
   * resolvable artifact bucket name that is NOT the fixed bucket the role covers, the
   * grant is provably insufficient and the project must be flagged.
   */
  it('flags the project when the artifact bucket name resolves to a different named bucket', () => {
    const template = templateWithArtifactLocation('other-artifacts-bucket');

    const result = evaluateProject(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.issue).toContain('other-artifacts-bucket');
  });
});
