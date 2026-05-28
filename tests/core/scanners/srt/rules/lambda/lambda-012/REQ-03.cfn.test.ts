import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-03 (CloudFormation): Lambda function with no execution role configured', () => {
  it('should pass when an AWS::Lambda::Function has no Role property', () => {
    const template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            // No Role property at all
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyFunction,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('should pass when an AWS::Serverless::Function has no Role property', () => {
    const template = {
      Resources: {
        MyServerlessFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'my-sam-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://bucket/key',
            // No Role property at all
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyServerlessFunction,
      logicalId: 'MyServerlessFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('should pass when one Lambda has no role even if another sibling Lambda has a role', () => {
    const template = {
      Resources: {
        FunctionWithoutRole: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'no-role-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
          },
        },
        FunctionWithRole: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'with-role-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            Role: 'SomeRoleArn',
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionWithoutRole,
      logicalId: 'FunctionWithoutRole',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
