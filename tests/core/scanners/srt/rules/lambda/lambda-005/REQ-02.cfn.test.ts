import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005CfnAdapterFactory();

function buildTemplate(statement: unknown): Template {
  return {
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
          Policies: [
            {
              PolicyName: 'FunctionPermissions',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [statement],
              },
            },
          ],
        },
      },
      MyFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          // !GetAtt LambdaExecutionRole.Arn resolves to the logical id string
          Role: 'LambdaExecutionRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template, logicalId: string) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId],
    logicalId,
  };
  return lambda005Control.run(factory.bind(context) as any, context);
}

describe('LAMBDA-005 REQ-02 (CloudFormation): wildcard action paired with wildcard resource on a Lambda execution role', () => {
  it('flags an execution role whose inline policy allows every action on every resource', () => {
    const template = buildTemplate({ Effect: 'Allow', Action: '*', Resource: '*' });

    const result = run(template, 'LambdaExecutionRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('LambdaExecutionRole');
    expect(result?.resourceType).toBe('AWS::IAM::Role');
  });

  it('flags the wildcard grant when the actions and resources are expressed as arrays', () => {
    const template = buildTemplate({ Effect: 'Allow', Action: ['*'], Resource: ['*'] });

    const result = run(template, 'LambdaExecutionRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: the same role, same wiring, but the grant is scoped to the
  // specific actions and resource ARNs the function needs (the compliant form of
  // this requirement). Absence-of-policy cases belong to other requirements.
  it('does not flag an execution role whose inline policy is scoped to specific actions and resource ARNs', () => {
    const template = buildTemplate({
      Effect: 'Allow',
      Action: ['s3:GetObject'],
      Resource: ['arn:aws:s3:::my-app-bucket/*'],
    });

    const result = run(template, 'LambdaExecutionRole');

    expect(result).toBeNull();
  });
});
