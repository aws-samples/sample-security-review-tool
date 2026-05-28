import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-02 (Terraform): unique execution role passes', () => {
  it('does not flag a Lambda whose execution role is not used by any other Lambda', () => {
    const functionA: TerraformResource = {
      address: 'aws_lambda_function.a',
      type: 'aws_lambda_function',
      name: 'a',
      values: {
        function_name: 'function-a',
        role: 'arn:aws:iam::123456789012:role/role-a',
      },
    } as unknown as TerraformResource;

    const functionB: TerraformResource = {
      address: 'aws_lambda_function.b',
      type: 'aws_lambda_function',
      name: 'b',
      values: {
        function_name: 'function-b',
        role: 'arn:aws:iam::123456789012:role/role-b',
      },
    } as unknown as TerraformResource;

    const functionC: TerraformResource = {
      address: 'aws_lambda_function.c',
      type: 'aws_lambda_function',
      name: 'c',
      values: {
        function_name: 'function-c',
        role: 'arn:aws:iam::123456789012:role/role-c',
      },
    } as unknown as TerraformResource;

    const allResources = [functionA, functionB, functionC];

    const factory = new Lambda012TfAdapterFactory();

    const context: TfContext = {
      projectName: 'test-project',
      resource: functionA,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('does not flag a Lambda with a unique role when other Lambdas share a different role', () => {
    const sharedA: TerraformResource = {
      address: 'aws_lambda_function.shared_a',
      type: 'aws_lambda_function',
      name: 'shared_a',
      values: {
        role: 'arn:aws:iam::123456789012:role/shared-role',
      },
    } as unknown as TerraformResource;

    const sharedB: TerraformResource = {
      address: 'aws_lambda_function.shared_b',
      type: 'aws_lambda_function',
      name: 'shared_b',
      values: {
        role: 'arn:aws:iam::123456789012:role/shared-role',
      },
    } as unknown as TerraformResource;

    const unique: TerraformResource = {
      address: 'aws_lambda_function.unique',
      type: 'aws_lambda_function',
      name: 'unique',
      values: {
        role: 'arn:aws:iam::123456789012:role/unique-role',
      },
    } as unknown as TerraformResource;

    const allResources = [sharedA, sharedB, unique];

    const factory = new Lambda012TfAdapterFactory();

    const context: TfContext = {
      projectName: 'test-project',
      resource: unique,
      allResources,
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
