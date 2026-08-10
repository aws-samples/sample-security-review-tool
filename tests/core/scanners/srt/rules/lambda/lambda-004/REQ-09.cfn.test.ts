import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09: AWS::Serverless::Function inherits Tracing from Globals.Function.
 *
 * SAM applies the template-level Globals.Function section to every serverless
 * function, and a value on the function itself takes precedence. Evaluating only
 * the resource properties flags functions whose tracing is enabled template-wide.
 */
describe('LAMBDA-004 REQ-09 (CFN): Tracing inherited from SAM Globals', () => {
  const factory = new Lambda004CfnAdapterFactory();

  const runFor = (template: Template, logicalId: string) => {
    const resource = template.Resources![logicalId];
    const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
    return lambda004Control.run(factory.bind(context), context);
  };

  const samFunction = (properties: Record<string, unknown> = {}) => ({
    Type: 'AWS::Serverless::Function',
    Properties: {
      FunctionName: 'my-sam-fn',
      Runtime: 'python3.12',
      Handler: 'index.handler',
      CodeUri: 's3://bucket/key',
      ...properties,
    },
  });

  const withGlobals = (tracing: unknown, resources: Template['Resources']) =>
    ({ Globals: { Function: { Tracing: tracing } }, Resources: resources }) as unknown as Template;

  it('does NOT flag a function with no Tracing when Globals.Function.Tracing is Active', () => {
    const template = withGlobals('Active', { MySamFunction: samFunction() });

    expect(runFor(template, 'MySamFunction')).toBeNull();
  });

  it('flags a function with no Tracing when Globals.Function.Tracing is PassThrough', () => {
    const template = withGlobals('PassThrough', { MySamFunction: samFunction() });

    expect(runFor(template, 'MySamFunction')?.check_id).toBe('LAMBDA-004');
  });

  it('flags a function with no Tracing when Globals.Function omits Tracing', () => {
    const template = {
      Globals: { Function: { Runtime: 'python3.12', Timeout: 30 } },
      Resources: { MySamFunction: samFunction() },
    } as unknown as Template;

    expect(runFor(template, 'MySamFunction')?.check_id).toBe('LAMBDA-004');
  });

  it('prefers the function\'s own Tracing over an Active global', () => {
    const template = withGlobals('Active', { MySamFunction: samFunction({ Tracing: 'PassThrough' }) });

    expect(runFor(template, 'MySamFunction')?.check_id).toBe('LAMBDA-004');
  });

  it('prefers the function\'s own Active Tracing over a PassThrough global', () => {
    const template = withGlobals('PassThrough', { MySamFunction: samFunction({ Tracing: 'Active' }) });

    expect(runFor(template, 'MySamFunction')).toBeNull();
  });

  it('does not apply Globals to AWS::Lambda::Function, which SAM Globals never covers', () => {
    const template = withGlobals('Active', {
      MyFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'my-fn',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          Role: 'arn:aws:iam::123456789012:role/lambda-role',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    });

    expect(runFor(template, 'MyFunction')?.check_id).toBe('LAMBDA-004');
  });

  it('does NOT flag when an inherited global Tracing value is an unresolved intrinsic', () => {
    const template = withGlobals({ Ref: 'TracingModeParam' }, { MySamFunction: samFunction() });

    expect(runFor(template, 'MySamFunction')).toBeNull();
  });
});
