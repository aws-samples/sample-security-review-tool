import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005CfnAdapterFactory();

/**
 * Builds a template with a Lambda function whose execution role carries a single
 * embedded permission document containing the given statement list.
 * `Role: 'ExecRole'` is the post-preprocessing form of `!GetAtt ExecRole.Arn`.
 */
function templateWithInlineStatements(statements: unknown[]): Template {
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
              PolicyName: 'FunctionPermissions',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: statements,
              },
            },
          ],
        },
      },
      HandlerFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Role: 'ExecRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function runRole(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, never>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['ExecRole'],
    logicalId: 'ExecRole',
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (CloudFormation) - empty inline policy statement list', () => {
  // Primary behavior owned by this requirement: an embedded permission document
  // with an empty statement list grants nothing, so it must not be flagged.
  it('passes when the Lambda execution role has an inline policy with an empty Statement list', () => {
    expect(runRole(templateWithInlineStatements([]))).toBeNull();
  });

  // Opposite outcome: same role, same embedded document, but the statement list
  // now contains a wildcard action on all resources - the requirement's violation.
  it('flags when the same inline policy document lists a wildcard action on all resources', () => {
    const result = runRole(
      templateWithInlineStatements([{ Effect: 'Allow', Action: '*', Resource: '*' }]),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('ExecRole');
  });
});
