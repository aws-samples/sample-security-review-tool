import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-02 (CloudFormation): unique execution role passes', () => {
  it('does not flag a Lambda whose execution role is not used by any other Lambda in the template', () => {
    const template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-a',
            Role: 'RoleA',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        FunctionB: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-b',
            Role: 'RoleB',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ServerlessFunctionC: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'function-c',
            Role: 'RoleC',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://bucket/key',
          },
        },
      },
    } as any;

    const factory = new Lambda012CfnAdapterFactory();

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.FunctionA,
      logicalId: 'FunctionA',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag a Serverless::Function with a unique role among mixed Lambda resource types', () => {
    const template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Role: 'SharedRole',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        FunctionB: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Role: 'SharedRole',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        ServerlessFunctionC: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Role: 'UniqueRoleForServerless',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://bucket/key',
          },
        },
      },
    } as any;

    const factory = new Lambda012CfnAdapterFactory();

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources.ServerlessFunctionC,
      logicalId: 'ServerlessFunctionC',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
