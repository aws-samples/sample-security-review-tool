import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-06 (CloudFormation): two Lambda functions share the same external execution role ARN', () => {
  it('flags both Lambda functions when they reference the same out-of-template role ARN', () => {
    const sharedRoleArn = 'arn:aws:iam::123456789012:role/external-shared-lambda-role';

    const template: Template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-a',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            Role: sharedRoleArn,
          },
        },
        FunctionB: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'function-b',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://bucket/code.zip',
            Role: sharedRoleArn,
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();

    const contextA: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionA,
      logicalId: 'FunctionA',
    };
    const contextB: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionB,
      logicalId: 'FunctionB',
    };

    const adapterA = factory.bind(contextA);
    const adapterB = factory.bind(contextB);

    const resultA = lambda012Control.run(adapterA, contextA);
    const resultB = lambda012Control.run(adapterB, contextB);

    expect(resultA).not.toBeNull();
    expect(resultA?.check_id).toBe('LAMBDA-012');
    expect(resultA?.resourceName).toBe('FunctionA');
    expect(resultA?.resourceType).toBe('AWS::Lambda::Function');
    expect(resultA?.status).toBe('Open');
    expect(resultA?.priority).toBe('HIGH');

    expect(resultB).not.toBeNull();
    expect(resultB?.check_id).toBe('LAMBDA-012');
    expect(resultB?.resourceName).toBe('FunctionB');
    expect(resultB?.resourceType).toBe('AWS::Serverless::Function');
    expect(resultB?.status).toBe('Open');
    expect(resultB?.priority).toBe('HIGH');
  });
});
