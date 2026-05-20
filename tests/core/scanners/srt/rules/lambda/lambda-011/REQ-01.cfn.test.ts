import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 / REQ-01 / CloudFormation', () => {
  it('flags a Lambda function when no CloudWatch alarm resources exist anywhere in the template', () => {
    const template: Template = {
      Resources: {
        MyLambdaFunction: {
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
      resource: template.Resources!.MyLambdaFunction,
      logicalId: 'MyLambdaFunction',
    };

    const factory = new Lambda011CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-011');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('AWS::Lambda::Function');
    expect(result!.resourceName).toBe('MyLambdaFunction');
    expect(result!.priority).toBe('HIGH');
    expect(result!.path).toBe('test-stack');
  });
});
