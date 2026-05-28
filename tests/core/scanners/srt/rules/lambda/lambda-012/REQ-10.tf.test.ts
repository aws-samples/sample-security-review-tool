import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-10 (Terraform): three or more Lambda functions share the same execution role', () => {
  const sharedRole = 'arn:aws:iam::123456789012:role/SharedLambdaRole';

  const functionA: TerraformResource = {
    address: 'aws_lambda_function.fn_a',
    type: 'aws_lambda_function',
    name: 'fn_a',
    values: {
      function_name: 'fn-a',
      role: sharedRole,
      runtime: 'nodejs20.x',
      handler: 'index.handler',
    },
  } as unknown as TerraformResource;

  const functionB: TerraformResource = {
    address: 'aws_lambda_function.fn_b',
    type: 'aws_lambda_function',
    name: 'fn_b',
    values: {
      function_name: 'fn-b',
      role: sharedRole,
      runtime: 'nodejs20.x',
      handler: 'index.handler',
    },
  } as unknown as TerraformResource;

  const functionC: TerraformResource = {
    address: 'aws_lambda_function.fn_c',
    type: 'aws_lambda_function',
    name: 'fn_c',
    values: {
      function_name: 'fn-c',
      role: sharedRole,
      runtime: 'nodejs20.x',
      handler: 'index.handler',
    },
  } as unknown as TerraformResource;

  const allResources = [functionA, functionB, functionC];
  const factory = new Lambda012TfAdapterFactory();

  const buildContext = (resource: TerraformResource): TfContext => ({
    projectName: 'test-project',
    resource,
    allResources,
  });

  it('flags fn_a because its execution role is shared with at least one other Lambda', () => {
    const ctx = buildContext(functionA);
    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.fn_a');
    expect(result?.status).toBe('Open');
  });

  it('flags fn_b because its execution role is shared with at least one other Lambda', () => {
    const ctx = buildContext(functionB);
    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.fn_b');
  });

  it('flags fn_c because its execution role is shared with at least one other Lambda', () => {
    const ctx = buildContext(functionC);
    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.fn_c');
  });
});
