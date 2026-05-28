import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-10 (CloudFormation): three or more Lambda functions share the same execution role', () => {
  const sharedRole = 'arn:aws:iam::123456789012:role/SharedLambdaRole';

  const template = {
    Resources: {
      FunctionA: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'fn-a',
          Role: sharedRole,
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
      FunctionB: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'fn-b',
          Role: sharedRole,
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
      FunctionC: {
        Type: 'AWS::Serverless::Function',
        Properties: {
          FunctionName: 'fn-c',
          Role: sharedRole,
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          CodeUri: 's3://bucket/key',
        },
      },
    },
  } as unknown as Template;

  const factory = new Lambda012CfnAdapterFactory();

  const buildContext = (logicalId: string): CfnContext => ({
    stackName: 'test-stack',
    template,
    resource: template.Resources![logicalId],
    logicalId,
  });

  it('flags FunctionA because its execution role is shared with at least one other Lambda', () => {
    const ctx = buildContext('FunctionA');
    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('FunctionA');
    expect(result?.status).toBe('Open');
  });

  it('flags FunctionB because its execution role is shared with at least one other Lambda', () => {
    const ctx = buildContext('FunctionB');
    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('FunctionB');
  });

  it('flags FunctionC (AWS::Serverless::Function) because its execution role is shared with at least one other Lambda', () => {
    const ctx = buildContext('FunctionC');
    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('FunctionC');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
  });
});
