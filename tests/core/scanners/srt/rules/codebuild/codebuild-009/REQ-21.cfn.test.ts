import { describe, expect, it } from 'vitest';

import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { Codebuild009Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const BUCKET = 'my-artifact-bucket';

function template(actions: string[]): Template {
  return {
    Resources: {
      BuildProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          // !Ref BuildRole resolves to the logical id string
          ServiceRole: 'BuildRole',
          Artifacts: {
            Type: 'S3',
            Location: BUCKET,
          },
          Source: { Type: 'NO_SOURCE' },
          Environment: {
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
            Type: 'LINUX_CONTAINER',
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
              PolicyName: 'artifact-bucket-access',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: actions,
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
    },
  } as unknown as Template;
}

function bindProject(tpl: Template): { adapter: Codebuild009Adapter; context: CfnContext } {
  const resource = (tpl.Resources as Record<string, Resource>)['BuildProject'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template: tpl,
    resource,
    logicalId: 'BuildProject',
  };
  const adapter = new Codebuild009CfnAdapterFactory().bind(context) as Codebuild009Adapter;
  return { adapter, context };
}

describe('CODEBUILD-009 (CloudFormation) - lower-cased action names still grant the required permissions', () => {
  // Primary behaviour owned by this requirement: IAM action matching is case insensitive.
  it('does not flag a project whose role allows s3:getbucketacl and s3:getbucketlocation in lower case on the artifact bucket', () => {
    const { adapter, context } = bindProject(
      template(['s3:getbucketacl', 's3:getbucketlocation']),
    );

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([]);
    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });

  // Opposite outcome: lower-cased action names that are not the required permissions must still be flagged.
  it('flags a project whose role allows lower-cased actions other than the two required bucket-inspection actions', () => {
    const { adapter, context } = bindProject(
      template(['s3:getobject', 's3:putobject']),
    );

    expect(adapter.bucketsMissingRequiredPermissions()).toEqual([BUCKET]);
    const result = codebuild009Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('BuildProject');
  });
});
