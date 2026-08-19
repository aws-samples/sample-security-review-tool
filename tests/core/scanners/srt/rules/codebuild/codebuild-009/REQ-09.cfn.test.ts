import { describe, expect, it } from 'vitest';
import { codebuild009Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.control.js';
import { Codebuild009CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/codebuild/codebuild-009/codebuild-009.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (CODEBUILD-009): CodeBuild project service roles must include both
 * s3:GetBucketAcl and s3:GetBucketLocation for any S3 bucket associated with
 * the project.
 *
 * Scenario under test: source and artifacts are both of type CODEPIPELINE, so
 * the project reads/writes the pipeline's S3 artifact bucket under its service
 * role. The role is defined in the same template and its policy grants neither
 * required permission -> expect a finding.
 */

const factory = new Codebuild009CfnAdapterFactory();

function buildTemplate(policyActions: string[]): Template {
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
        },
      },
      BuildRolePolicy: {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'build-policy',
          Roles: ['BuildRole'],
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: policyActions,
                Resource: '*',
              },
            ],
          },
        },
      },
      PipelineProject: {
        Type: 'AWS::CodeBuild::Project',
        Properties: {
          Name: 'pipeline-project',
          // !Ref BuildRole resolves to the logical id string after preprocessing
          ServiceRole: 'BuildRole',
          Environment: {
            Type: 'LINUX_CONTAINER',
            ComputeType: 'BUILD_GENERAL1_SMALL',
            Image: 'aws/codebuild/standard:7.0',
          },
          Source: { Type: 'CODEPIPELINE' },
          Artifacts: { Type: 'CODEPIPELINE' },
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template): CfnContext {
  const resources = template.Resources as Record<string, any>;
  return {
    stackName: 'pipeline-stack',
    template,
    resource: resources['PipelineProject'],
    logicalId: 'PipelineProject',
  };
}

describe('CODEBUILD-009 (CloudFormation) - CODEPIPELINE-managed source and artifacts', () => {
  it('flags a CODEPIPELINE project whose in-template role policy grants neither get-bucket-ACL nor get-bucket-location', () => {
    const template = buildTemplate(['s3:PutObject', 's3:GetObject']);
    const context = contextFor(template);
    const adapter = factory.bind(context);

    const result = codebuild009Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('CODEBUILD-009');
    expect(result?.resourceName).toBe('PipelineProject');
    expect(result?.resourceType).toBe('AWS::CodeBuild::Project');
  });

  // Opposite outcome: nearest input that flips the verdict - the same
  // CODEPIPELINE project and role, but the policy now grants both permissions.
  it('does not flag the same CODEPIPELINE project when the role policy grants both permissions', () => {
    const template = buildTemplate([
      's3:PutObject',
      's3:GetObject',
      's3:GetBucketAcl',
      's3:GetBucketLocation',
    ]);
    const context = contextFor(template);
    const adapter = factory.bind(context);

    expect(codebuild009Control.run(adapter, context)).toBeNull();
  });
});
