import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const NARROW_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
      Resource: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/worker:*',
    },
  ],
};

const WILDCARD_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: '*',
      Resource: '*',
    },
  ],
};

const LAMBDA_TRUST_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: { Service: 'lambda.amazonaws.com' },
      Action: 'sts:AssumeRole',
    },
  ],
};

/** Post-preprocessing template: !GetAtt LambdaExecutionRole.Arn collapses to the logical id string. */
function buildTemplate(broadPolicyRoles: string[]): Template {
  return {
    Resources: {
      LambdaExecutionRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: LAMBDA_TRUST_POLICY,
          Policies: [
            {
              PolicyName: 'narrow-logging',
              PolicyDocument: NARROW_DOCUMENT,
            },
          ],
        },
      },
      WorkerFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Role: 'LambdaExecutionRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
      PipelineAutomationRole: {
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
      BroadAutomationPolicy: {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'broad-automation',
          PolicyDocument: WILDCARD_DOCUMENT,
          Roles: broadPolicyRoles,
        },
      },
    },
  } as unknown as Template;
}

function evaluateRole(template: Template, logicalId: string) {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId]!,
    logicalId,
  };
  const adapter = new Lambda005CfnAdapterFactory().bind(context);
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-14 (CloudFormation): wildcard policy bound to a different identity', () => {
  // Primary behavior owned by REQ-14: a wildcard document attached to another role
  // confers no privilege on the assessed Lambda execution role.
  it('passes the Lambda execution role when the wildcard policy targets a different role', () => {
    const template = buildTemplate(['PipelineAutomationRole']);

    expect(evaluateRole(template, 'LambdaExecutionRole')).toBeNull();
  });

  // Opposite outcome: only the binding of the wildcard document changes.
  it('flags the Lambda execution role when the same wildcard policy targets it', () => {
    const template = buildTemplate(['LambdaExecutionRole']);

    const result = evaluateRole(template, 'LambdaExecutionRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('LambdaExecutionRole');
  });
});
