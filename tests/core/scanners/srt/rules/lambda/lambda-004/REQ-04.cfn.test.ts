import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 CFN - Tracing configuration present but Mode value missing or empty', () => {
  const factory = new Lambda004CfnAdapterFactory();

  function buildContext(logicalId: string, resource: Record<string, unknown>): CfnContext {
    const template: Template = {
      Resources: {
        [logicalId]: resource as never,
      },
    } as Template;
    return {
      stackName: 'test-stack',
      template,
      resource: template.Resources![logicalId],
      logicalId,
    };
  }

  it('flags AWS::Lambda::Function when TracingConfig is present but Mode is missing', () => {
    const ctx = buildContext('MyFunction', {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'my-fn',
        TracingConfig: {},
      },
    });

    const adapter = factory.bind(ctx);
    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('AWS::Lambda::Function');
    expect(result!.resourceName).toBe('MyFunction');
  });

  it('flags AWS::Lambda::Function when TracingConfig.Mode is an empty string', () => {
    const ctx = buildContext('MyFunction', {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'my-fn',
        TracingConfig: { Mode: '' },
      },
    });

    const adapter = factory.bind(ctx);
    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
  });

  it('flags AWS::Serverless::Function when Tracing property is an empty string', () => {
    const ctx = buildContext('MyServerlessFunction', {
      Type: 'AWS::Serverless::Function',
      Properties: {
        FunctionName: 'my-sam-fn',
        Tracing: '',
      },
    });

    const adapter = factory.bind(ctx);
    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('AWS::Serverless::Function');
  });
});
