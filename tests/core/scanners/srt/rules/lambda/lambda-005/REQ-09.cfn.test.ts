import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (LAMBDA-005): An execution role used by a Lambda function that is attached to a
 * predefined administrator-level managed policy (full control over the account) must be flagged.
 */

const factory = new Lambda005CfnAdapterFactory();

const buildTemplate = (managedPolicyArns: string[]): Template => ({
  Resources: {
    LambdaExecutionRole: {
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
        // !GetAtt LambdaExecutionRole.Arn resolves to the logical id after preprocessing
        Role: 'LambdaExecutionRole',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        Code: { ZipFile: 'exports.handler = async () => {};' },
      },
    },
  } as unknown as Template['Resources'],
});

const evaluateRole = (template: Template) => {
  const resources = template.Resources as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'lambda-005-stack',
    template,
    resource: resources['LambdaExecutionRole'] as Resource,
    logicalId: 'LambdaExecutionRole',
  };
  return lambda005Control.run(factory.bind(context), context);
};

describe('LAMBDA-005 REQ-09 (CloudFormation)', () => {
  it('flags a Lambda execution role attached to the AdministratorAccess managed policy', () => {
    const result = evaluateRole(buildTemplate(['arn:aws:iam::aws:policy/AdministratorAccess']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('LambdaExecutionRole');
    expect(result?.resourceType).toBe('AWS::IAM::Role');
  });

  // Opposite outcome: same role, same wiring, only the breadth of the managed policy changes.
  it('does not flag a Lambda execution role attached to a narrowly scoped managed policy', () => {
    const result = evaluateRole(buildTemplate([
      'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
    ]));

    expect(result).toBeNull();
  });
});
