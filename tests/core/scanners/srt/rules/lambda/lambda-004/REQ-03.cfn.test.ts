import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (CloudFormation):
 * Scenario: Lambda function has tracing configuration with mode set to PassThrough.
 * Expected behavior: flag.
 * Rationale: PassThrough mode only propagates tracing context to downstream services
 * and does not cause Lambda itself to record trace segments. This does not satisfy
 * the requirement that X-Ray tracing be enabled for the function.
 */
describe('LAMBDA-004 / REQ-03 / CloudFormation: PassThrough tracing mode should be flagged', () => {
  const factory = new Lambda004CfnAdapterFactory();

  it('flags AWS::Lambda::Function when TracingConfig.Mode is PassThrough', () => {
    const template: Template = {
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'my-function',
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
            Code: { ZipFile: 'exports.handler = async () => {};' },
            TracingConfig: {
              Mode: 'PassThrough',
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

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-004');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
    expect(result?.resourceName).toBe('MyFunction');
    expect(result?.status).toBe('Open');
  });

  it('flags AWS::Serverless::Function when Tracing is set to PassThrough', () => {
    const template: Template = {
      Resources: {
        MySamFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            Runtime: 'nodejs18.x',
            Handler: 'index.handler',
            CodeUri: './src',
            Tracing: 'PassThrough',
          },
        },
      },
    };

    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.MySamFunction,
      logicalId: 'MySamFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-004');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
    expect(result?.resourceName).toBe('MySamFunction');
    expect(result?.status).toBe('Open');
  });
});
