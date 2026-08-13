import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LAMBDA_ROLE_ID = 'FunctionExecutionRole';

/**
 * Builds a template with a Lambda function whose execution role is attached only to the
 * supplied managed policy ARNs. Values are written post-preprocessing (Role resolves to
 * the role's logical id).
 */
function buildTemplate(managedPolicyArns: string[]): Template {
  return {
    Resources: {
      [LAMBDA_ROLE_ID]: {
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
          ManagedPolicyArns: managedPolicyArns,
        },
      },
      ProcessorFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'processor',
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Role: LAMBDA_ROLE_ID,
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function evaluateRole(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[LAMBDA_ROLE_ID],
    logicalId: LAMBDA_ROLE_ID,
  };
  const adapter = new Lambda005CfnAdapterFactory().bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (CloudFormation) — narrowly scoped predefined permission sets', () => {
  // Primary behavior owned by this requirement: a minimal, purpose-built managed policy must not be flagged.
  it('does not flag a Lambda execution role attached only to the minimal log-writing managed policy', () => {
    const result = evaluateRole(
      buildTemplate(['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole']),
    );

    expect(result).toBeNull();
  });

  it('does not flag a Lambda execution role attached only to several narrowly scoped managed policies', () => {
    const result = evaluateRole(
      buildTemplate([
        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
        'arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
        'arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole',
      ]),
    );

    expect(result).toBeNull();
  });

  // Opposite outcome: same role, same wiring — only the breadth of the predefined
  // permission set changes, which is what the rule turns on.
  it('flags the same Lambda execution role when the attached managed policy is administrator-level', () => {
    const result = evaluateRole(buildTemplate(['arn:aws:iam::aws:policy/AdministratorAccess']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe(LAMBDA_ROLE_ID);
  });
});
