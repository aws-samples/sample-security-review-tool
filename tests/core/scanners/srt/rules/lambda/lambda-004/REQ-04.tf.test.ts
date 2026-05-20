import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 TF - tracing_config block present but mode value missing or empty', () => {
  const factory = new Lambda004TfAdapterFactory();

  function buildContext(resource: TerraformResource): TfContext {
    return {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };
  }

  it('flags aws_lambda_function when tracing_config block is present but mode key is missing', () => {
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      values: {
        function_name: 'my-fn',
        tracing_config: [{}],
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(resource);
    const adapter = factory.bind(ctx);
    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('aws_lambda_function');
    expect(result!.resourceName).toBe('aws_lambda_function.my_fn');
  });

  it('flags aws_lambda_function when tracing_config.mode is an empty string', () => {
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      values: {
        function_name: 'my-fn',
        tracing_config: [{ mode: '' }],
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(resource);
    const adapter = factory.bind(ctx);
    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
  });

  it('flags aws_lambda_function when tracing_config is provided as an object with missing mode', () => {
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_fn',
      type: 'aws_lambda_function',
      name: 'my_fn',
      values: {
        function_name: 'my-fn',
        tracing_config: { mode: '' },
      },
    } as unknown as TerraformResource;

    const ctx = buildContext(resource);
    const adapter = factory.bind(ctx);
    const result = lambda004Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-004');
    expect(result!.status).toBe('Open');
  });
});
