import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 - CloudFormation - Lambda function with no tracing configuration', () => {
  it('flags AWS::Lambda::Function when TracingConfig is not specified', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: {
              ZipFile: 'exports.handler = async () => {};',
            },
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyFunction,
      logicalId: 'MyFunction',
    };

    const factory = new Lambda004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-004');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.resourceName).toBe('MyFunction');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });

  it('flags AWS::Serverless::Function when Tracing is not specified', () => {
    const template: Template = {
      Resources: {
        MyServerlessFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'my-serverless-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://my-bucket/code.zip',
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MyServerlessFunction,
      logicalId: 'MyServerlessFunction',
    };

    const factory = new Lambda004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Serverless::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-004');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
    expect(result?.resourceName).toBe('MyServerlessFunction');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
