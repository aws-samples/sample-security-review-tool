import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import { TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 - Terraform - Lambda has tracing mode set to an unrecognized value', () => {
  it('flags aws_lambda_function when tracing_config.mode is an unrecognized value', () => {
    const resource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: [
          { mode: 'Enabled' }, // unrecognized; only "Active" is valid
        ],
      },
    } as any;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Lambda004TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('aws_lambda_function');
    expect(result!.resourceName).toBe('aws_lambda_function.my_function');
  });

  it('flags aws_lambda_function when tracing_config.mode is "PassThrough"', () => {
    const resource = {
      address: 'aws_lambda_function.passthrough_fn',
      type: 'aws_lambda_function',
      name: 'passthrough_fn',
      values: {
        function_name: 'passthrough-fn',
        runtime: 'python3.11',
        handler: 'app.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: [
          { mode: 'PassThrough' }, // unrecognized for this rule
        ],
      },
    } as any;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Lambda004TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
  });

  it('flags aws_lambda_function when tracing_config.mode is a completely invalid string', () => {
    const resource = {
      address: 'aws_lambda_function.invalid_fn',
      type: 'aws_lambda_function',
      name: 'invalid_fn',
      values: {
        function_name: 'invalid-fn',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: [
          { mode: 'NotAValidMode' },
        ],
      },
    } as any;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Lambda004TfAdapterFactory();
    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
  });
});
