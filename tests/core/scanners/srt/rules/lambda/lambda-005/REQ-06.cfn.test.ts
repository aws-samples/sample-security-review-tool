import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06 (LAMBDA-005): a wildcard-action/wildcard-resource statement whose Effect is
 * Deny grants no privilege and must NOT be flagged. The Allow variant of the same
 * statement is owned by the primary wildcard-grant requirement and is included here
 * only as the opposite-outcome case.
 */

const factory = new Lambda005CfnAdapterFactory();

function buildTemplate(wildcardEffect: 'Deny' | 'Allow'): Template {
  return {
    Resources: {
      ExecRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { Service: 'lambda.amazonaws.com' },
                Action: 'sts:AssumeRole',
              },
            ],
          },
          Policies: [
            {
              PolicyName: 'inline',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    // The statement under test: every action on every resource.
                    Effect: wildcardEffect,
                    Action: '*',
                    Resource: '*',
                  },
                  {
                    // A narrowly scoped permitting statement.
                    Effect: 'Allow',
                    Action: ['logs:PutLogEvents'],
                    Resource: ['arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/fn:*'],
                  },
                ],
              },
            },
          ],
        },
      },
      Fn: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Code: { ZipFile: 'exports.handler = async () => {};' },
          // !Ref ExecRole resolves to the logical id string.
          Role: 'ExecRole',
        },
      },
    },
  } as unknown as Template;
}

function runRole(template: Template) {
  const resource = (template.Resources as Record<string, never>)['ExecRole'];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ExecRole',
  };
  return lambda005Control.run(factory.bind(context), context);
}

describe('LAMBDA-005 REQ-06 (CloudFormation)', () => {
  it('passes when the Lambda execution role denies all actions on all resources', () => {
    expect(runRole(buildTemplate('Deny'))).toBeNull();
  });

  // Opposite outcome: the same statement as a grant is over-permissive.
  it('flags the same statement when its effect permits all actions on all resources', () => {
    const result = runRole(buildTemplate('Allow'));
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('ExecRole');
  });
});
