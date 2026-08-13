import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-04 (LAMBDA-005): A Lambda execution role whose inline policy allows a
 * service-prefixed wildcard action (e.g. "s3:*") on "Resource": "*" must be flagged
 * as the wildcard-action / wildcard-resource anti-pattern.
 */

const factory = new Lambda005CfnAdapterFactory();

/** Builds a template where LambdaExecRole is assumed by a Lambda function and carries one inline statement. */
function templateWith(statement: Record<string, unknown>): Template {
  return {
    Resources: {
      LambdaExecRole: {
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
              PolicyName: 'function-permissions',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [statement],
              },
            },
          ],
        },
      },
      // Role resolves to the logical id string after preprocessing of !GetAtt LambdaExecRole.Arn
      ProcessorFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Role: 'LambdaExecRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function runOnRole(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, never>;
  const context: CfnContext = {
    stackName: 'lambda-005-req-04-stack',
    template,
    resource: resources['LambdaExecRole'],
    logicalId: 'LambdaExecRole',
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-04 (CloudFormation): service-prefixed wildcard action on all resources', () => {
  it('flags an execution role granting "s3:*" on "Resource": "*"', () => {
    const result = runOnRole(
      templateWith({ Effect: 'Allow', Action: 's3:*', Resource: '*' }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('LambdaExecRole');
    expect(result?.resourceType).toBe('AWS::IAM::Role');
  });

  it('flags the same grant when "s3:*" appears inside an Action array on "Resource": "*"', () => {
    const result = runOnRole(
      templateWith({ Effect: 'Allow', Action: ['logs:CreateLogStream', 's3:*'], Resource: ['*'] }),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: the service-prefixed wildcard action remains, but it is no longer
  // paired with a wildcard resource, so this requirement's violation does not hold.
  it('does not flag "s3:*" scoped to a specific resource ARN', () => {
    const result = runOnRole(
      templateWith({
        Effect: 'Allow',
        Action: 's3:*',
        Resource: 'arn:aws:s3:::my-app-bucket/*',
      }),
    );

    expect(result).toBeNull();
  });
});
