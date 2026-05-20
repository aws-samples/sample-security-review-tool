import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (CloudFormation): Lambda function's tracing configuration block is
 * conditionally included via an unresolvable condition (e.g., Fn::If).
 *
 * Expected: PASS — when it cannot be determined at analysis time whether the
 * tracing configuration is present/active, the rule must not flag the
 * resource to avoid false positives.
 */
describe('LAMBDA-004 REQ-07 (CFN): unresolvable conditional tracing configuration', () => {
  const factory = new Lambda004CfnAdapterFactory();

  it('does not flag AWS::Lambda::Function whose TracingConfig.Mode is an Fn::If intrinsic', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'fn-with-conditional-tracing',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { ZipFile: 'exports.handler = async () => {};' },
        TracingConfig: {
          Mode: { 'Fn::If': ['EnableTracingCondition', 'Active', 'PassThrough'] },
        },
      },
    } as never;

    const context: CfnContext = {
      stackName: 'test-stack',
      template: { Resources: { MyFunction: resource } } as never,
      resource,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag AWS::Lambda::Function whose entire TracingConfig is an Fn::If intrinsic', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'fn-with-conditional-tracing-block',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { ZipFile: 'exports.handler = async () => {};' },
        TracingConfig: {
          Mode: { Ref: 'TracingModeParameter' },
        },
      },
    } as never;

    const context: CfnContext = {
      stackName: 'test-stack',
      template: { Resources: { MyFunction: resource } } as never,
      resource,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag AWS::Serverless::Function whose Tracing property is an Fn::If intrinsic', () => {
    const resource = {
      Type: 'AWS::Serverless::Function',
      Properties: {
        FunctionName: 'sam-fn-with-conditional-tracing',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        CodeUri: 's3://bucket/key',
        Tracing: { 'Fn::If': ['EnableTracingCondition', 'Active', 'PassThrough'] },
      },
    } as never;

    const context: CfnContext = {
      stackName: 'test-stack',
      template: { Resources: { MySamFunction: resource } } as never,
      resource,
      logicalId: 'MySamFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
