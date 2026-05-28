import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 / REQ-01 / CloudFormation: Two Lambda functions sharing the same in-template execution role', () => {
  const template: Template = {
    Resources: {
      SharedRole: {
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
        },
      },
      FunctionA: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'function-a',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Code: { ZipFile: 'exports.handler = async () => {};' },
          // !GetAtt SharedRole.Arn -> resolves to "SharedRole" after preprocessing
          Role: 'SharedRole',
        },
      },
      FunctionB: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'function-b',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Code: { ZipFile: 'exports.handler = async () => {};' },
          // !GetAtt SharedRole.Arn -> resolves to "SharedRole" after preprocessing
          Role: 'SharedRole',
        },
      },
    },
  };

  const factory = new Lambda012CfnAdapterFactory();

  const buildContext = (logicalId: string): CfnContext => ({
    stackName: 'test-stack',
    template,
    resource: template.Resources![logicalId],
    logicalId,
  });

  it('flags FunctionA because it shares its execution role with FunctionB', () => {
    const ctx = buildContext('FunctionA');
    const adapter = factory.bind(ctx);

    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('FunctionA');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.status).toBe('Open');
  });

  it('flags FunctionB because it shares its execution role with FunctionA', () => {
    const ctx = buildContext('FunctionB');
    const adapter = factory.bind(ctx);

    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('FunctionB');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.status).toBe('Open');
  });

  it('also flags shared roles for AWS::Serverless::Function resources', () => {
    const samTemplate: Template = {
      Resources: {
        SharedRole: {
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
          },
        },
        SamFunctionA: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: './src',
            Role: 'SharedRole',
          },
        },
        SamFunctionB: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: './src',
            Role: 'SharedRole',
          },
        },
      },
    };

    const ctx: CfnContext = {
      stackName: 'test-stack',
      template: samTemplate,
      resource: samTemplate.Resources!['SamFunctionA'],
      logicalId: 'SamFunctionA',
    };

    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('SamFunctionA');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
  });
});
