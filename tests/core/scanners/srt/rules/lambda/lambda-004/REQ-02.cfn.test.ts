import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 REQ-02 (CloudFormation): Lambda function has tracing configuration with mode set to Active', () => {
  it('should pass when AWS::Lambda::Function has TracingConfig with Mode set to Active', () => {
    const template: Template = {
      Resources: {
        MyLambdaFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            TracingConfig: {
              Mode: 'Active',
            },
          },
        },
      },
    };

    const logicalId = 'MyLambdaFunction';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Lambda004CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('should pass when AWS::Serverless::Function has Tracing set to Active', () => {
    const template: Template = {
      Resources: {
        MyServerlessFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'my-serverless-function',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://my-bucket/my-code.zip',
            Tracing: 'Active',
          },
        },
      },
    };

    const logicalId = 'MyServerlessFunction';
    const resource = template.Resources![logicalId];

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId,
    };

    const factory = new Lambda004CfnAdapterFactory();
    expect(factory.appliesTo(resource.Type)).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
