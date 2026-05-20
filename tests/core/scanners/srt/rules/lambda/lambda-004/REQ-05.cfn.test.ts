import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.cfn.js';
import { CfnContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 - CloudFormation - Lambda has tracing mode set to an unrecognized value', () => {
  it('flags AWS::Lambda::Function when TracingConfig.Mode is an unrecognized value', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'my-function',
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { ZipFile: 'exports.handler = async () => {};' },
        TracingConfig: {
          Mode: 'Enabled', // unrecognized; only "Active" is valid
        },
      },
    };

    const template = { Resources: { MyFunction: resource } } as any;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: resource as any,
      logicalId: 'MyFunction',
    };

    const factory = new Lambda004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Lambda::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('AWS::Lambda::Function');
    expect(result!.resourceName).toBe('MyFunction');
  });

  it('flags AWS::Serverless::Function when Tracing is an unrecognized value', () => {
    const resource = {
      Type: 'AWS::Serverless::Function',
      Properties: {
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
        CodeUri: 's3://bucket/key',
        Tracing: 'PassThrough', // unrecognized; only "Active" is valid
      },
    };

    const template = { Resources: { MyServerlessFunction: resource } } as any;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: resource as any,
      logicalId: 'MyServerlessFunction',
    };

    const factory = new Lambda004CfnAdapterFactory();
    expect(factory.appliesTo('AWS::Serverless::Function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('AWS::Serverless::Function');
    expect(result!.resourceName).toBe('MyServerlessFunction');
  });

  it('flags AWS::Lambda::Function when TracingConfig.Mode is a completely invalid string', () => {
    const resource = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        FunctionName: 'my-function',
        Runtime: 'python3.11',
        Handler: 'app.handler',
        Role: 'arn:aws:iam::123456789012:role/lambda-role',
        Code: { ZipFile: 'def handler(event, context): pass' },
        TracingConfig: {
          Mode: 'NotAValidMode',
        },
      },
    };

    const template = { Resources: { MyFunction: resource } } as any;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: resource as any,
      logicalId: 'MyFunction',
    };

    const factory = new Lambda004CfnAdapterFactory();
    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });
});
