import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-06: Lambda function tracing mode value depends on an unresolvable condition.
 *
 * When the tracing mode value cannot be determined at analysis time (e.g. it is a
 * CloudFormation intrinsic function such as { Ref: <Parameter> } or { 'Fn::If': [...] }),
 * the rule cannot assert non-compliance. To avoid false positives, the rule should not flag.
 */
describe('LAMBDA-004 REQ-06 (CFN): unresolvable tracing mode value should not be flagged', () => {
  const factory = new Lambda004CfnAdapterFactory();

  it('does NOT flag AWS::Lambda::Function whose TracingConfig.Mode is an unresolved Ref to a parameter', () => {
    const template: Template = {
      Parameters: {
        TracingModeParam: {
          Type: 'String',
          Default: 'Active',
        },
      },
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-fn',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            TracingConfig: {
              Mode: { Ref: 'TracingModeParam' },
            },
          },
        },
      },
    };

    const resource = template.Resources!.MyFunction;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag AWS::Lambda::Function whose TracingConfig.Mode comes from an Fn::If', () => {
    const template: Template = {
      Conditions: {
        EnableTracing: { 'Fn::Equals': [{ Ref: 'AWS::Region' }, 'us-east-1'] },
      },
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-fn',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            TracingConfig: {
              Mode: { 'Fn::If': ['EnableTracing', 'Active', 'PassThrough'] },
            },
          },
        },
      },
    };

    const resource = template.Resources!.MyFunction;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does NOT flag AWS::Serverless::Function whose Tracing value is an unresolved Ref', () => {
    const template: Template = {
      Parameters: {
        TracingModeParam: {
          Type: 'String',
          Default: 'Active',
        },
      },
      Resources: {
        MySamFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            FunctionName: 'my-sam-fn',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            CodeUri: 's3://bucket/key',
            Tracing: { Ref: 'TracingModeParam' },
          },
        },
      },
    };

    const resource = template.Resources!.MySamFunction;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MySamFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
