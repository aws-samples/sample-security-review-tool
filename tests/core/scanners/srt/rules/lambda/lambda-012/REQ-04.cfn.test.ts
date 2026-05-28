import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-04 (CloudFormation): distinct execution roles per Lambda', () => {
  const factory = new Lambda012CfnAdapterFactory();

  // After cfn preprocessing, !GetAtt RoleA.Arn -> "RoleA" and !GetAtt RoleB.Arn -> "RoleB"
  // Each Lambda has its own separately-defined IAM role resource (distinct identities),
  // even though the policy contents on each role are identical.
  const template: Template = {
    Resources: {
      RoleA: {
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
              PolicyName: 'IdenticalPolicy',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  { Effect: 'Allow', Action: 'logs:*', Resource: '*' },
                ],
              },
            },
          ],
        },
      },
      RoleB: {
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
              PolicyName: 'IdenticalPolicy',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  { Effect: 'Allow', Action: 'logs:*', Resource: '*' },
                ],
              },
            },
          ],
        },
      },
      FunctionA: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'function-a',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Code: { ZipFile: 'exports.handler = async () => {};' },
          // After preprocessing this resolves to the string "RoleA"
          Role: 'RoleA',
        },
      },
      FunctionB: {
        Type: 'AWS::Serverless::Function',
        Properties: {
          FunctionName: 'function-b',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          CodeUri: 's3://bucket/key',
          // After preprocessing this resolves to the string "RoleB"
          Role: 'RoleB',
        },
      },
    },
  } as unknown as Template;

  it('passes for FunctionA when it has its own distinct execution role identity', () => {
    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionA,
      logicalId: 'FunctionA',
    };

    const adapter = factory.bind(ctx);
    expect(adapter.sharesExecutionRole).toBe(false);

    const result = lambda012Control.run(adapter, ctx);
    expect(result).toBeNull();
  });

  it('passes for FunctionB when it has its own distinct execution role identity', () => {
    const ctx: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionB,
      logicalId: 'FunctionB',
    };

    const adapter = factory.bind(ctx);
    expect(adapter.sharesExecutionRole).toBe(false);

    const result = lambda012Control.run(adapter, ctx);
    expect(result).toBeNull();
  });
});
